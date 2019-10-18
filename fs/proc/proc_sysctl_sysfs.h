#ifndef SYSFS_CTL_H
#define SYSFS_CTL_H

struct sysfs_ctl_dir;

struct sysfs_ctl_dir_attrs *sysfs_ctl_register_table(struct ctl_table_set *set,
		const char *path, struct ctl_table *table);

void sysfs_ctl_unregister_table(struct sysfs_ctl_dir_attrs *da);

int sysfs_ctl_init(void);

#endif //SYSFS_CTL_H
