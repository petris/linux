#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/kobject.h>
#include <linux/sysctl.h>
#include <linux/kernfs.h>
#include <linux/sysfs.h>

#include "proc_sysctl_sysfs.h"

struct sysfs_ctl_attr {
	struct attribute attr;
};

struct sysfs_ctl_dir_attrs {
	struct sysfs_ctl_dir_attrs __rcu *next;
	struct ctl_table *table;
	struct sysfs_ctl_dir *dir;
	int attrs_nmemb;
	struct sysfs_ctl_attr attrs[];
};

struct sysfs_ctl_dir {
	struct kobject kobj;
	struct sysfs_ctl_dir_attrs __rcu *attrs;
	void *ns;
};

#define kobj_to_sysfs_ctl_dir(k) \
		container_of((k), struct sysfs_ctl_dir, kobj)

static int sysfs_ctl_unregister_dir_table(struct sysfs_ctl_dir *d,
		struct ctl_table *entry);

static DEFINE_MUTEX(sysfs_ctl_dir_attrs_lock);

/***** sysfs_ctl kobject ***********************************************/

struct ctl_table *sysfs_ctl_kobj_to_ctl_table(const struct kobject *kobj,
		const struct attribute *a)
{
	const struct sysfs_ctl_dir *d = kobj_to_sysfs_ctl_dir(kobj);
	const struct sysfs_ctl_dir_attrs *da;

	rcu_read_lock();
	for (da = rcu_dereference(d->attrs); da; da = rcu_dereference(da->next)) {
		if ((void*)a > (void*)da &&
		    (void*)a < (void*)&da->attrs[da->attrs_nmemb]) {
			struct ctl_table *t = da->table;
			for (; t; t++) {
				if (!strcmp(t->procname, a->name)) {
					rcu_read_unlock();
					return t;
				}
			}
			WARN(1, "Table was modified, %s not found in %s\n",
					a->name, kobject_name(kobj));
			break;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static ssize_t sysfs_ctl_show(struct kobject *kobj, struct attribute *a, char *val)
{
	struct ctl_table *t = sysfs_ctl_kobj_to_ctl_table(kobj, a);
	ssize_t rtn = -EIO;

	if (t->proc_handler) {
		size_t len = PAGE_SIZE;
		loff_t ppos = 0;
		mm_segment_t seg;

		seg = get_fs();
		set_fs(KERNEL_DS);
		rtn = t->proc_handler(t, 0, val, &len, &ppos);
		set_fs(seg);
		rtn = rtn ?: len;
	}

	return rtn;
}

static ssize_t sysfs_ctl_store(struct kobject *kobj, struct attribute *a, const char *val, size_t size)
{
	struct ctl_table *t = sysfs_ctl_kobj_to_ctl_table(kobj, a);
	ssize_t rtn = -EIO;

	if (!strcmp("uevent", a->name)) {
		rtn = kobject_synth_uevent(kobj, val, size);
	} else if (t->proc_handler) {
		loff_t ppos = 0;
		mm_segment_t seg;

		seg = get_fs();
		set_fs(KERNEL_DS);
		rtn = t->proc_handler(t, 1, (char*)val, &size, &ppos);
		set_fs(seg);
	}

	return rtn ?: size;
}

static struct sysfs_ops sysfs_ctl_ops = {
	.show = sysfs_ctl_show,
	.store = sysfs_ctl_store,
};

static const struct kobj_ns_type_operations *ctl_sysfs_child_ns_type(struct kobject *kobj)
{
	return &net_ns_type_operations;
}

static const void *ctl_sysfs_namespace(struct kobject *kobj)
{
	return kobj_to_sysfs_ctl_dir(kobj)->ns;
}

static void sysfs_ctl_release(struct kobject *kobj)
{
	const struct sysfs_ctl_dir *d = kobj_to_sysfs_ctl_dir(kobj);

	WARN_ON(d->attrs);
	kfree(d);
}

static int sysfs_ctl_uevent(struct kset *kset, struct kobject *kobj,
		struct kobj_uevent_env *env)
{
	const struct sysfs_ctl_dir *d = kobj_to_sysfs_ctl_dir(kobj);
	const struct sysfs_ctl_dir_attrs *da;
	const char varname[] = "ATTRIBUTES=";
	const char truncmsg[] = "...";
	int i, first = 1;

	if (env->envp_idx >= ARRAY_SIZE(env->envp))
		return -ENOMEM;

	if (env->buflen + strlen(truncmsg) + strlen(varname) >= sizeof(env->buf))
		return -ENOMEM;

	env->envp[env->envp_idx++] = &env->buf[env->buflen];
	strcpy(&env->buf[env->buflen], varname);
	env->buflen += strlen(varname);

	rcu_read_lock();
	for (da = rcu_dereference(d->attrs); da; da = rcu_dereference(da->next)) {
		for (i = 0; i < da->attrs_nmemb; i++) {
			const char *name = da->attrs[i].attr.name;

			if (first)
				first = 0;
			else
				strcpy(&env->buf[env->buflen++], " ");

			if (strlen(truncmsg) + strlen(name) + env->buflen + 2
					>= sizeof(env->buf)) {
				strcpy(&env->buf[env->buflen], truncmsg);
				env->buflen += strlen(truncmsg);
				goto out;
			}
			strcpy(&env->buf[env->buflen], name);
			env->buflen += strlen(name);
		}
	}
out:	rcu_read_unlock();
	env->buflen++;

	return 0;
}

static struct kset_uevent_ops sysfs_ctl_kset_ops = {
	.uevent = sysfs_ctl_uevent,
};

static struct kset *sysfs_ctl_kset;

static struct attribute uevent_attr = { .name = "uevent", .mode = 0200 };

static struct attribute *default_attr[] = {
	&uevent_attr,
	NULL
};

static inline struct kobj_type *sysfs_ctl_ktype(enum kobj_ns_type ns_type)
{
	static struct kobj_type kt[] = {
		[KOBJ_NS_TYPE_NONE] = {
			.sysfs_ops = &sysfs_ctl_ops,
			.release = &sysfs_ctl_release,
			.default_attrs = default_attr,
		},
#ifdef CONFIG_NET
		[KOBJ_NS_TYPE_NET] = {
			.child_ns_type = &ctl_sysfs_child_ns_type,
			.sysfs_ops = &sysfs_ctl_ops,
			.release = &sysfs_ctl_release,
			.namespace = &ctl_sysfs_namespace,
			.default_attrs = default_attr,
		},
#endif
	};

	return &kt[ns_type];
}

/***** sysfs_ctl hierarchy management ***********************************/

/** Create a new sysfs_ctl directory */
static struct sysfs_ctl_dir *sysfs_ctl_dir_new(struct sysfs_ctl_dir *parent,
		enum kobj_ns_type ns_type, void *ns, const char *name)
{
	struct sysfs_ctl_dir *d = kzalloc(sizeof(*d), GFP_KERNEL);
	int err;

	if (!d) {
		return ERR_PTR(-ENOMEM);
	}

	d->ns = ns;

	pr_info("Create '%s' %d\n", name, ns_type);
	if (!parent)
		d->kobj.kset = sysfs_ctl_kset;
	err = kobject_init_and_add(&d->kobj, sysfs_ctl_ktype(ns_type),
			parent ? &parent->kobj : NULL, name); // FIXME
	if (err) {
		kfree(d);
		pr_info("Failed to create dir %d %d %p %s\n", ns_type, err, ns, name);
		return ERR_PTR(err);
	}

	return d;
}

/** Look up a child by its name */
static struct sysfs_ctl_dir *sysfs_ctl_dir_child(struct sysfs_ctl_dir *parent,
		const char *name, void *ns)
{
	struct sysfs_ctl_dir *child;
	struct kernfs_node *n;

	n = kernfs_find_and_get_ns(parent->kobj.sd, name, ns);
	if (!n)
		return NULL;

	child = n->priv;
	kernfs_put(n);

	return child;
}

static struct sysfs_ctl_dir *sysfs_ctl_dir_get(struct sysfs_ctl_dir *d)
{
	struct sysfs_ctl_dir *dr = kobj_to_sysfs_ctl_dir(kobject_get(&d->kobj));
	BUG_ON(!dr);
	return dr;
}

static void sysfs_ctl_dir_put(struct sysfs_ctl_dir *d)
{
	kobject_put(&d->kobj);
}

/** Lookup a directory, create it if it doesn't exist */
static struct sysfs_ctl_dir *sysfs_ctl_get(const char *path,
		enum kobj_ns_type ns_type, void *ns)
{
	const char *name, *nextname;
	struct kernfs_node *n1, *n2;
	struct sysfs_ctl_dir *d1, *d2;

	d1 = NULL;
	kernfs_get(sysfs_ctl_kset->kobj.sd);
	n1 = sysfs_ctl_kset->kobj.sd;

	for (name = path; name; name = nextname) {
		int namelen; char buf[128];

		nextname = strchr(name, '/');
		if (nextname) {
			namelen = nextname - name;
			nextname++;
		} else {
			namelen = strlen(name);
		}
		if (namelen == 0)
			continue;

		BUG_ON(namelen >= sizeof buf - 1);

		strncpy(buf, name, namelen);
		buf[namelen] = 0;
		n2 = kernfs_find_and_get_ns(n1, buf, d1 ? ns : NULL);
		if (n2) {
			d2 = sysfs_ctl_dir_get(kobj_to_sysfs_ctl_dir(n2->priv));
		} else {
			d2 = sysfs_ctl_dir_new(d1, ns_type, ns, buf);
			if (IS_ERR(d2)) {
				goto err;
			}

			kernfs_get(d2->kobj.sd);
			n2 = d2->kobj.sd;
		}

		if (d1) sysfs_ctl_dir_put(d1);
		d1 = d2;
		kernfs_put(n1);
		n1 = n2;
	}

	kernfs_put(n1);

	// TODO: Check ns_type

	return d1;

err:	sysfs_ctl_dir_put(d1);
	kernfs_put(n1);
	return d2;
}

static int _sysfs_ctl_unregister_table(struct sysfs_ctl_dir_attrs *da)
{
	struct sysfs_ctl_dir_attrs * __rcu * da_tmp;
	struct sysfs_ctl_dir *d = da->dir;
	struct ctl_table *entry;

	while (da->attrs_nmemb-- > 0) {
		sysfs_remove_file_ns(&d->kobj, &da->attrs[da->attrs_nmemb].attr,
				d->ns);
	}

	for (da_tmp = &d->attrs; *da_tmp; da_tmp = &((*da_tmp)->next)) {
		if (*da_tmp == da) {
			rcu_assign_pointer(*da_tmp, da->next);
			break;
		}
	}
	WARN_ON(*da_tmp != da->next);


	for (entry = da->table; entry->procname; entry++) {
		if (entry->child) {
			WARN_ON(sysfs_ctl_unregister_dir_table(
				sysfs_ctl_dir_child(d, entry->procname, d->ns),
				entry->child));
		}
	}

	sysfs_ctl_dir_put(da->dir);
	synchronize_rcu();
	kfree(da);

	return 0;
}

void sysfs_ctl_unregister_table(struct sysfs_ctl_dir_attrs *da)
{
	int err;

	mutex_lock(&sysfs_ctl_dir_attrs_lock);
	err = _sysfs_ctl_unregister_table(da);
	mutex_unlock(&sysfs_ctl_dir_attrs_lock);

	WARN_ON(err);
}

static int sysfs_ctl_unregister_dir_table(struct sysfs_ctl_dir *d,
		struct ctl_table *entry)
{
	struct sysfs_ctl_dir_attrs *da;

	for (da = d->attrs; da; da = da->next) {
		if (da->table == entry) {
			return _sysfs_ctl_unregister_table(da);
		}
	}

	return -ENOENT;
}

struct sysfs_ctl_dir_attrs *sysfs_ctl_register_table(struct ctl_table_set *set,
	const char *path, struct ctl_table *table)
{
	struct ctl_table_root *root = set->dir.header.root;
	struct ctl_table *entry;

	struct sysfs_ctl_dir_attrs *da;
	struct sysfs_ctl_dir *d;
	char *newpath = NULL;
	int nmemb, err;
	void *ns = NULL;

	if (root->ns_type == KOBJ_NS_TYPE_NET) {
		ns = container_of(set, struct net, sysctls);
	}

	d = sysfs_ctl_get(path, root->ns_type, ns);
	if (IS_ERR(d)) {
		pr_info("iFail %ld\n", (long)d);
		return ERR_CAST(d);
	}

	mutex_lock(&sysfs_ctl_dir_attrs_lock);
	for (da = d->attrs; da; da = da->next) {
		if (da->table == table) {
			pr_warn("Trying to reregister the same table/set "
				"combination in %s\n", path);
			err = -EEXIST;
			goto err0;
		}
	}

	for (nmemb = 0, entry = table; entry->procname; entry++) {
		if (0 == (entry->mode & ~0777))
			nmemb++;
		if (entry->child) {
			if (!newpath) {
				newpath = kmalloc(PATH_MAX, GFP_KERNEL);
				if (!newpath) {
					err = -ENOMEM;
					goto err0;
				}
			}
			snprintf(newpath, PATH_MAX, "%s/%s", path, entry->procname);
			da = sysfs_ctl_register_table(set, newpath, entry->child);
			if (IS_ERR(da)) {
				err = PTR_ERR(da);
				goto err1;
			}
		}
	}

	da = kzalloc(sizeof(*da) + sizeof(da->attrs[0]) * nmemb, GFP_KERNEL);
	if (!da) {
		err = -ENOMEM;
		goto err1;
	}
	da->attrs_nmemb = nmemb;
	da->table = table;
	da->dir = d;

	for (nmemb = 0, entry = table; entry->procname; entry++) {
		if (0 != (entry->mode & ~0777))
			continue;

		sysfs_attr_init(&da->attrs[nmemb].attr);
		da->attrs[nmemb].attr.mode = entry->mode;
		da->attrs[nmemb].attr.name = entry->procname;

		err = sysfs_create_file_ns(&d->kobj, &da->attrs[nmemb].attr, ns);
		if (err)
			goto err2;

		nmemb++;
	}

	rcu_assign_pointer(da->next, d->attrs);
	rcu_assign_pointer(d->attrs, da);
	mutex_unlock(&sysfs_ctl_dir_attrs_lock);

	kfree(newpath);
	kobject_uevent(&d->kobj, KOBJ_ADD);
	return da;

err2:	while (nmemb-- > 0) {
		sysfs_remove_file_ns(&d->kobj, &da->attrs[nmemb].attr, ns);
	}
	for (entry = table; entry->procname; entry++); // Find last entry
err1:	while (entry-- != table) {
		if (entry->child) {
			WARN_ON(sysfs_ctl_unregister_dir_table(
				sysfs_ctl_dir_child(d, entry->procname, ns), entry->child));
		}
	}
	kfree(newpath);
err0:	mutex_unlock(&sysfs_ctl_dir_attrs_lock);
	sysfs_ctl_dir_put(d);
	pr_err("sysfs_ctl_register_table returns %d\n", err);
	return ERR_PTR(err);
}

int sysfs_ctl_init(void)
{
#ifdef CONFIG_NET
	kobj_ns_type_register(&net_ns_type_operations);
#endif
	sysfs_ctl_kset = kset_create_and_add("ctl", &sysfs_ctl_kset_ops, NULL);

	return sysfs_ctl_kset ? 0 : -EIO;
}
