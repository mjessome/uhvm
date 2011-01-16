/* See LICENSE file for copyright and license details. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>

#include <mntent.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <dirent.h>
#include <syslog.h>
#include <fcntl.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <hal/libhal.h>
#include <hal/libhal-storage.h>

/* ============================
 * = Macros
 * ============================
 */

/* feel free to alter these to your liking */

/* NOTE: you may want to use the sync mount option if you plan
 * to cold eject your usb drives. Even though the side-effects
 * are probably not worth it.
 */
#define MOUNT_CMD_PATH "/bin/mount"
#define UMOUNT_CMD_PATH "/bin/umount"
#define DEFAULT_MNT_OPTIONS "noexec,nosuid,nodev,users"
#define BASE_MNT_DIR "/media/"
#define HOOK_PATH "/etc/uhvm/hooks"

/* not user controlled */
#define LOCKFILE "/var/run/uhvm.pid"
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define FREE_WRAP(ptr) do { free(ptr); ptr = NULL; } while (0)
#define INIT_NODE(p1, p2) \
    do { \
        p1->mountp = p2->mountp; \
        p1->did = p2->did; \
        p1->dev = p2->dev; \
        p1->label = p2->label; \
        p1->fstype = p2->fstype; \
        p1->opt = p2->opt; \
        p1->volume = p2->volume; \
        p1->drive = p2->drive; \
    } while (0)
#define EXEC_CMD(args) \
    g_spawn_sync( \
                  "/", \
                  (args), \
                  (gchar **)NULL, \
                  0, \
                  (GSpawnChildSetupFunc)NULL, \
                  (gpointer)NULL, \
                  (gchar **)NULL, \
                  (gchar **)NULL, \
                  (gint *)NULL, \
                  (GError **)NULL)

/* ============================
 * = Structs
 * ============================
 */

struct device_t {
    char *mountp;              /* mount point */
    char *did;                 /* volume's unique id */
    char *dev;                 /* device associated with this volume */
    char *label;               /* volume's label */
    char *fstype;              /* filesystem type */
    char *opt;                 /* mount options */
    char *uuid;                /* device uuid */
    int use_fstab;             /* true if this device has an fstab entry
                                 before inserting the device */
    int use_uuid;              /* true if was mounted by uuid */
    int should_remove_entry;   /* true if upon removal of the device
                                 an entry in fstab needs to be removed */
    char** hook;               /* hook[0] - mount
                                  hook[1] - umount */

    LibHalVolume *volume;
    LibHalDrive *drive;
    struct device_t *next;
};

/* ============================
 * = Globals
 * ============================
 */

/* the dbus connection handler */
static DBusConnection *dbus_conn = NULL;
/* the main hal context handler */
static LibHalContext *hal_ctx = NULL;
/* the head of a linked list of currently mounted devices */
static struct device_t *head = NULL;
static struct device_t *tail = NULL;
/* the main loop handler */
static GMainLoop *loop = NULL;
/* file descriptor for LOCKFILE */
static int pid_fd = -1;
/* flag used for debugging */
static int debug_mode_flag = 0;

/* ============================
 * = Function declarations
 * ============================
 */

/* (de)/initialization functions */
static int init_uhvm(void);
static int init_dbus(DBusError *error);
static int init_hal(void);
static void deinit(void);

/* callback functions */
static void device_added(LibHalContext *context, const char *did);
static void device_removed(LibHalContext *context, const char *did);

/* functions related to the device list */
static struct device_t *get_device(char *mountp, const char *did,
                                   char *dev, char *label,
                                   const char *fstype,
                                   LibHalVolume *volume,
                                   LibHalDrive *drive);
static void add_to_device_list(struct device_t *device);
static void remove_from_device_list(struct device_t *prev,
                                    struct device_t *curr);
static void free_device(struct device_t *device);

/* functions related to device hooks */
char *get_hook(struct device_t *device, char * hook_type);
int run_hook(int hook, struct device_t *device);

/* functions related to how the volume manager behaves when
 * a new device is inserted */
static int is_mounted(const struct device_t *device);
static char *get_mount_point(const char *dev, const char *label);
static int resolve_symlink(const char *symlnk, char *d, size_t d_len);
static void consider_fstab(struct device_t *device);
static int do_mount(const struct device_t *device);
static int do_umount(const struct device_t *device);
static int add_mtab_entry(const struct device_t *device);
static int add_fstab_entry(const struct device_t *device);
static int remove_fstab_entry(const struct device_t *device);

/* general function helpers */
static inline int file_exists(const char *path);
static void cleanup(int sig);
static int is_running(void);
static void debug_dump_device(const struct device_t *device);

int
main(int argc, char *argv[])
{
    int c;

    static struct option long_options[] = {
        { "debug", no_argument, NULL, 'd' },
        { NULL, 0, NULL, 0 }
    };

    while ((c = getopt_long(argc, argv, "d", long_options,
                            NULL)) != -1) {
        switch (c) {
        case 'd':
            debug_mode_flag = 1;
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    if (debug_mode_flag)
        setvbuf(stdout, (char *)NULL, _IONBF, 0); /* avoid surprises */

    if (init_uhvm() < 0)
        return EXIT_FAILURE;

    openlog(argv[0], LOG_PID, LOG_DAEMON);
    signal(SIGTERM, cleanup);

    if (!debug_mode_flag) {
        if (daemon(0, 0) < 0 || is_running()) {
            deinit();
            return EXIT_FAILURE;
        }
    }

    loop = g_main_loop_new((GMainContext *)NULL, FALSE);
    g_main_run(loop);

    deinit();
    return EXIT_SUCCESS;
}

static int
init_uhvm(void)
{
    DBusError error;

    dbus_error_init(&error);
    if (init_dbus(&error) < 0) {
        if (dbus_error_is_set(&error)) {
            syslog(LOG_ERR, "%s:%d: %s:%s", __FILE__, __LINE__,
                   error.name, error.message);
            dbus_error_free(&error);
            return -1;
        }
    }

    return init_hal();
}

static int
init_dbus(DBusError *error)
{
    if (!(dbus_conn = dbus_bus_get(DBUS_BUS_SYSTEM, error)))
        return -1;
    dbus_connection_setup_with_g_main(dbus_conn, (GMainContext *)NULL);
    dbus_connection_flush(dbus_conn);
    return 0;
}

static int
init_hal(void)
{
    DBusError error;

    if (!(hal_ctx = libhal_ctx_new()))
        return -1;

    libhal_ctx_set_dbus_connection(hal_ctx, dbus_conn);

    libhal_ctx_set_device_added(hal_ctx, device_added);
    libhal_ctx_set_device_removed(hal_ctx, device_removed);

    dbus_error_init(&error);
    if (!libhal_device_property_watch_all(hal_ctx, &error)) {
        if (dbus_error_is_set(&error)) {
            syslog(LOG_ERR, "%s:%d: %s:%s", __FILE__, __LINE__,
                   error.name, error.message);
            dbus_error_free (&error);
            libhal_ctx_free (hal_ctx);
            return -1;
        }
    }

    if (!libhal_ctx_init(hal_ctx, &error)) {
        if (dbus_error_is_set(&error)) {
            syslog(LOG_ERR, "%s:%d: %s:%s", __FILE__, __LINE__,
                   error.name, error.message);
            dbus_error_free(&error);
            libhal_ctx_free(hal_ctx);
            return -1;
        }
    }

    return 0;
}

static void
deinit(void)
{
    struct device_t *iter, *tmp;

    if (hal_ctx) {
        libhal_ctx_shutdown(hal_ctx, (DBusError *)NULL);
        libhal_ctx_free(hal_ctx);
    }

    dbus_connection_unref(dbus_conn);

    iter = head;

    while (iter) {
        tmp = iter;
        if (!is_mounted(iter))
            /* don't care to check the return values */
            do_umount(iter);
        rmdir(iter->mountp);
        if (iter->should_remove_entry)
            remove_fstab_entry(iter);
        iter = iter->next;
        free_device(tmp);
    }

    if (pid_fd >= 0)
        if (close(pid_fd) < 0) /* releases lock */
            syslog(LOG_ERR, "%s:%d: %s", __FILE__, __LINE__, strerror(errno));
    closelog();
}

/* Callback function, called when a new device has been inserted. */
static void
device_added(LibHalContext *context, const char *did)
{
    const char *dudi, *fstype;
    char *dev, *mountp, *mountable, *label, *locked_reason;
    LibHalVolume *volume;
    LibHalDrive *drive;
    struct device_t *device;

    if (libhal_device_property_exists(context, did, "info.locked",
                                      (DBusError *)NULL)
            && libhal_device_get_property_bool(context, did, "info.locked",
                                               (DBusError *)NULL)) {
        if (debug_mode_flag) {
            locked_reason = libhal_device_get_property_string(
                                context, did, "info.locked.reason",
                                (DBusError *)NULL);
            if (locked_reason) {
                if (debug_mode_flag)
                    printf("%s%d: %s\n", __FILE__, __LINE__, locked_reason);
                libhal_free_string(locked_reason);
            }
        }
        return;
    }

    if (!libhal_device_query_capability(context, did, "volume",
                                        (DBusError *)NULL))
        return;
    label = libhal_device_get_property_string(context, did, "volume.label",
                                              (DBusError *)NULL);
    if (!(mountable = libhal_device_get_property_string(
                          context, did, "volume.fsusage", (DBusError *)NULL))
            || strcmp(mountable, "filesystem"))
        goto out;
    if (!(volume = libhal_volume_from_udi(context, did)))
        goto out;
    if (!(dudi = libhal_volume_get_storage_device_udi(volume)))
        goto out;
    if (!(drive = libhal_drive_from_udi(context, dudi)))
        goto out;
    if (!libhal_drive_is_hotpluggable(drive)
            && !libhal_drive_uses_removable_media(drive))
        goto out;
    if (!(fstype = libhal_volume_get_fstype(volume)))
        goto out;
    if (!(dev = libhal_device_get_property_string(context, did, "block.device",
                                                  (DBusError *)NULL)))
        goto out;
    mountp = get_mount_point(dev, label);
    if (!mountp)
        goto out;
    device = get_device(mountp, did, dev, label, fstype, volume, drive);
    if (!device)
        goto out;
    consider_fstab(device);

    device->hook = malloc(2*sizeof(char*)); 
    if(!file_exists(HOOK_PATH)) {
        device->hook[0] = get_hook(device, "mount");
        device->hook[1] = get_hook(device, "umount");
    }

    if (file_exists(device->mountp) < 0)
        mkdir(device->mountp, 0750);
    do_mount(device) < 0 ? free_device(device) : add_to_device_list(device);

    if (device) {
        if (!add_fstab_entry(device))
            device->should_remove_entry = 1;
        if (debug_mode_flag)
            debug_dump_device(device);
    }

    if (device->hook[0]) run_hook(0, device);

out:
    if (mountable)
        libhal_free_string(mountable);
    if (label)
        libhal_free_string(label);
}

/* Callback function, called when a device has been removed. */
static void
device_removed(LibHalContext *context __attribute__ ((unused)),
               const char *did)
{
    char *mountp = NULL;
    struct device_t *iter = head, *prev = NULL;

    while (iter) {
        if (!strcmp(did, iter->did)) {
            mountp = iter->mountp;
            if (!file_exists(mountp)) {
                if (!is_mounted(iter))
                    if (do_umount(iter))
                        syslog(LOG_ERR, "%s:%d: %s", __FILE__, __LINE__,
                               strerror(errno));
                if (rmdir(mountp) < 0)
                    syslog(LOG_ERR, "%s:%d: %s", __FILE__, __LINE__,
                           strerror(errno));
                if (iter->should_remove_entry && remove_fstab_entry(iter))
                    syslog(LOG_ERR, "%s:%d: %s", __FILE__, __LINE__,
                           "cannot remove fstab entry");
                if(iter->hook[1]) run_hook(1, iter);
                remove_from_device_list(prev, iter);
            }
            return;
        }
        prev = iter;
        iter = iter->next;
    }
}

static struct device_t *
get_device(char *mountp, const char *did, char *dev, char *label,
           const char *fstype, LibHalVolume *volume, LibHalDrive *drive) {
    struct device_t *device = malloc(sizeof(*device));

    if (device) {
        device->mountp = mountp;
        device->did = strdup(did);
        device->dev = dev;
        device->label = strdup(label);
        device->fstype = strdup(fstype);
        device->opt = NULL;
        device->volume = volume;
        device->drive = drive;
        device->next = NULL;
        device->use_fstab = 0;
        device->use_uuid = 1;
        device->should_remove_entry = 0;

        /* retrieve the uuid of the device */
        if ((did = strrchr(device->did, '/'))) {
            did = strstr(did, "uuid");
            if (did) {
                did = strchr(did, '_');
                if (did) {
                    ++did;
                    device->uuid = malloc(sizeof(did));
                    strcpy(device->uuid, did);
                    char* c = device->uuid;
                    while((c=strrchr(c, '_')))
                        *c = '-';
                }
            }
        }

        if (!device->did || !device->label || !device->fstype) {
            /* freeing null pointers is GOOD */
            FREE_WRAP(device->did);
            FREE_WRAP(device->label);
            FREE_WRAP(device->fstype);
            free_device(device);
            device = NULL;
        }
    }

    return device;
}

static void
add_to_device_list(struct device_t *device)
{
    if (!device)
        return;

    if (!head) {
        head = device;
        tail = head;
        INIT_NODE(head, device);
    } else {
        tail->next = device;
        tail = tail->next;
        INIT_NODE(tail, device);
    }
}

static void
remove_from_device_list(struct device_t *prev, struct device_t *curr)
{
    if (!curr)
        return;

    if (curr == head) {
        head = curr->next;
    } else if (curr == tail) {
        tail = prev;
        tail->next = NULL;
    } else {
        if (!prev)
            return;
        prev->next = curr->next;
    }

    free_device(curr);
}

static void
free_device(struct device_t *device)
{
    if (!device)
        return;

    FREE_WRAP(device->mountp);
    FREE_WRAP(device->did);
    if (device->dev)
        libhal_free_string(device->dev);
    FREE_WRAP(device->label);
    FREE_WRAP(device->fstype);
    FREE_WRAP(device->opt);
    if (device->volume)
        libhal_volume_free(device->volume);
    if (device->drive)
        libhal_drive_free(device->drive);

    FREE_WRAP(device);
}

char *
get_hook(struct device_t *device, char *hook_type)
{
    char *hook = malloc(255);
    snprintf(hook, 255, "%s/%s.%s", HOOK_PATH, device->uuid, hook_type);

    if(!file_exists(hook)) {
        return hook;
    }
    free(hook);
    return NULL;
}

int
run_hook(int hook, struct device_t *device)
{
        EXEC_CMD(((char* []) {
            device->hook[hook], device->dev,
            device->mountp, device->label,
            device->fstype, (char*) NULL
            }));
        return 0;
}

static int
is_mounted(const struct device_t *device)
{
    FILE *mtab;
    struct mntent *entry;

    mtab = setmntent("/etc/mtab", "r");
    if (!mtab)
        return -1;

    while ((entry = getmntent(mtab))) {
        if ((device->use_uuid && strstr(entry->mnt_fsname, device->uuid))
            || !strcmp(entry->mnt_fsname, device->dev)) {
            endmntent(mtab);
            return 0;
        }
    }

    endmntent(mtab);
    return -1;
}

static char *
get_mount_point(const char *dev, const char *label)
{
    const char *extra;
    char *mountp, *dev_tmp;
    size_t len;
    struct dirent *dirent;
    DIR *dir;

    if (!(dev_tmp = strrchr(dev, '/')))
        return NULL;

    ++dev_tmp;
    len = strlen(dev_tmp) + 1 + strlen(BASE_MNT_DIR);
    extra = dev_tmp;
    if (label && strcmp(label, "")) {
        if ((dir = opendir(BASE_MNT_DIR))) {
            dirent = readdir(dir);
            while (dirent) {
                if (!strcmp(dirent->d_name, label))
                    goto out;
                dirent = readdir(dir);
            }
        }

        len = strlen(label) + 1 + strlen(BASE_MNT_DIR);
        extra = label;
    }

out:
    mountp = malloc(len);
    if (mountp)
        snprintf(mountp, len, "%s%s", BASE_MNT_DIR, extra);
    return mountp;
}

/*
 * This function will fail if the last symlink points
 * to a file whose path is defined relative to the symlink.
 */
static int
resolve_symlink(const char *restrict symlnk, char *restrict d, size_t d_len)
{
    char file[d_len], buf[d_len];
    ssize_t len;
    size_t f_len = strlen(symlnk) + 1;
    struct stat bf;

    if (f_len > d_len)
        return -1;
    memcpy(file, symlnk, f_len);
    do {
        len = readlink(file, buf, sizeof(buf) - 1);
        if (len < 0) {
            if (lstat(file, &bf) < 0)
                return -1;
            if (!file_exists(file) && !S_ISLNK(bf.st_mode))
                break;
            return -1;
        }
        buf[len] = '\0';
        memcpy(file, buf, len + 1);
    } while (1);

    memcpy(d, file, strlen(file) + 1);
    return 0;
}

/*
 * Open /etc/fstab and check if the inserted device
 * has a rule and if it does, change the mount point
 * and options associated with it. If it is a mount
 * point for another device do not use it. If it does
 * not have a rule, the device is not altered.
 */
static void
consider_fstab(struct device_t *device)
{
    FILE *fp, *mtab;
    struct mntent *entry, *i;
    char rlink[1024], *tmp, *str;
    size_t len;

    if (!device)
        return;

    if (!(fp = setmntent("/etc/fstab", "r")))
        return;

    while ((entry = getmntent(fp))) {
        /* check if we have an entry in fstab that suits our needs */
        if ((!strcmp(device->dev, entry->mnt_fsname)
                && (device->use_uuid = 0))
                || (device->uuid && strstr(entry->mnt_fsname, "UUID=")
                    && strstr(entry->mnt_fsname, device->uuid))
                || (strstr(entry->mnt_fsname, "LABEL=")
                    && strstr(entry->mnt_fsname, device->label))
                || (!resolve_symlink(entry->mnt_fsname, rlink, 1024)
                    && !strcmp(rlink, device->dev))) {
            tmp = device->mountp;
            device->mountp = strdup(entry->mnt_dir);
            device->opt = strdup(entry->mnt_opts);
            if (!device->opt || !device->mountp) {
                FREE_WRAP(device->mountp);
                FREE_WRAP(device->opt);
                device->mountp = tmp;
            } else {
                if (!(str = strrchr(device->dev, '/')))
                    break; /* this will cause mount points to be stacked */
                ++str;
                if (!(mtab = setmntent("/etc/mtab", "r")))
                    goto out;
                device->use_fstab = 1;
                len = strlen(str) + 1 + strlen(BASE_MNT_DIR);
                tmp = device->mountp;
                while ((i = getmntent(mtab))) {
                    /* check if someone else uses our mount point */
                    if (!strcmp(i->mnt_dir, device->mountp)) {
                        device->mountp = malloc(len);
                        if (!device->mountp) {
                            device->mountp = tmp;
                        } else {
                            snprintf(device->mountp, len, "%s%s", BASE_MNT_DIR, str);
                        }
                        break;
                    }
                }
                endmntent(mtab);
            }
            break;
        }
    }
out:
    endmntent(fp);
}

static int
do_mount(const struct device_t *device)
{
    if (!device)
        return -1;

    
    if (add_mtab_entry(device)) return -1;
    return EXEC_CMD(
        ((char * []) {
             MOUNT_CMD_PATH,
             "-n",
             "-t", device->fstype,
             "-o", (!device->opt) ? DEFAULT_MNT_OPTIONS : device->opt,
             "-U", device->uuid,
             device->mountp,
             (char *)NULL
    })) ? 0 : -1;
}

static int
do_umount(const struct device_t *device)
{
    if (!device)
        return -1;

    return EXEC_CMD(
    ((char * []) {
        UMOUNT_CMD_PATH, device->mountp, (char *)NULL
    })) ? 0 : -1;
}

static int
add_mtab_entry(const struct device_t *device)
{
    FILE *mtab;
    struct mntent entry;
    char fsname[128];

    if (!device)
        return -1;
    mtab = setmntent("/etc/mtab", "a");
    if (!mtab)
        return -1;

    if (device->use_uuid && device->uuid)
        snprintf(fsname, 128, "UUID=%s", device->uuid);
    else
        strcpy(fsname, device->dev);

    entry.mnt_fsname = fsname;
    entry.mnt_dir = device->mountp;
    entry.mnt_type = device->fstype;
    entry.mnt_opts = (!device->opt) ? DEFAULT_MNT_OPTIONS : device->opt;
    entry.mnt_freq = 0;
    entry.mnt_passno = 0;

    addmntent(mtab, &entry);
    endmntent(mtab);
    return 0;
}

static int
add_fstab_entry(const struct device_t *device)
{
    FILE *fstab;
    struct mntent entry;
    char fsname[128];

    if (!device || device->use_fstab)
        return -1;
    fstab = setmntent("/etc/fstab", "a");
    if (!fstab)
        return -1;

    if(device->use_uuid && device->uuid)
        snprintf(fsname, 128, "UUID=%s", device->uuid);
    else
        strcpy(fsname, device->dev);

    entry.mnt_fsname = fsname;
    entry.mnt_dir = device->mountp;
    entry.mnt_type = device->fstype;
    entry.mnt_opts = (!device->opt) ? DEFAULT_MNT_OPTIONS : device->opt;
    entry.mnt_freq = 0;
    entry.mnt_passno = 0;

    addmntent(fstab, &entry);
    endmntent(fstab);
    return 0;
}

static int
remove_fstab_entry(const struct device_t *device)
{
    FILE *fstab = NULL, *line_pp = NULL;
    char buf[BUFSIZ];
    int lines = 0, i = 0;

    if (!device || device->use_fstab)
        return -1;

    line_pp = popen("wc -l /etc/fstab | awk '{print $1}'", "r");
    if (!line_pp)
        return -1;

    if (!fgets(buf, sizeof buf, line_pp)) {
        pclose(line_pp);
        return -1;
    }

    pclose(line_pp);
    lines = atoi(buf);

    fstab = fopen("/etc/fstab", "r+");
    if (!fstab)
        return -1;

    char tmp[lines][BUFSIZ];
    while (!feof(fstab) && fgets(tmp[i], BUFSIZ, fstab))
        ++i;

    if (ferror(fstab))
        goto fail;

    rewind(fstab);
    if (ftruncate(fileno(fstab), 0) < 0) {
        syslog(LOG_ERR, "%s:%d: %s", __FILE__, __LINE__,
               strerror(errno));
        goto fail;
    }

    i = 0;
    while (i < lines) {
        if (!((device->use_uuid && device->uuid
            && strstr(tmp[i], "UUID=") && strstr(tmp[i], device->uuid))
            || strstr(tmp[i], device->dev))) {

            fprintf(fstab, "%s", tmp[i]);
        }
        ++i;
    }

    fclose(fstab);
    return 0;

fail:
    if (fstab)
        fclose(fstab);
    return -1;
}

static inline int
file_exists(const char *s)
{
    struct stat sb;
    return ((stat(s, &sb) < 0 && errno == ENOENT) ? -ENOENT : 0);
}

static void
cleanup(int sig __attribute__ ((unused)))
{
    g_main_loop_quit(loop);
}

/*
 * Check if uhvm is already running, the caller has to make sure that the log
 * file has been opened and the new instance has been daemonized.
 */
static int
is_running(void)
{
    char buf[16];
    int serrno;

    pid_fd = open(LOCKFILE, O_RDWR | O_CREAT, LOCKMODE);
    if (pid_fd < 0 || flock(pid_fd, LOCK_EX | LOCK_NB) < 0
            || ftruncate(pid_fd, 0) < 0)
        goto out;

    snprintf(buf, sizeof(buf), "%jd\n", (intmax_t)getpid());
    if (write(pid_fd, buf, strlen(buf)) != (int)strlen(buf))
        goto out;
    return 0;

out:
    serrno = errno;
    if (pid_fd != -1)
        if (close(pid_fd) < 0)
            syslog(LOG_ERR, "%s:%d: %s", __FILE__, __LINE__,
                   strerror(errno));
    errno = serrno;
    pid_fd = -1;
    syslog(LOG_ERR, "%s:%d: %s", __FILE__, __LINE__,
           strerror(errno));
    return -1;
}

static void
debug_dump_device(const struct device_t *device)
{
    if (!device)
        return;

    printf("Volume info: %s\n", (!device->did) ? "(null)" : device->did);
    printf("Device: %s\n", (!device->dev) ? "(null)" : device->dev);
    printf("Label: %s\n", (!device->label) ? "(null)" : device->label);
    printf("UUID: %s\n", (!device->uuid) ? "(null)" : device->uuid);
    printf("Filesystem type: %s\n",
           (!device->fstype) ? "(null)" : device->fstype);
    printf("Mount options: %s\n",
           (!device->opt) ? DEFAULT_MNT_OPTIONS : device->opt);
    printf("Mount point: %s\n",
           (!device->mountp) ? "(null)" : device->mountp);
    printf("Uses /etc/fstab: %d\n", device->use_fstab);
    printf("Uses uuid: %d\n", device->use_uuid);
    printf("Cleanup after /etc/fstab: %d\n", device->should_remove_entry);
    printf("Mount Hook: %s\n", (!device->hook[0]) ? "None" : device->hook[0]);
    printf("Unmount Hook: %s\n", (!device->hook[1]) ? "None" : device->hook[1]);
}

