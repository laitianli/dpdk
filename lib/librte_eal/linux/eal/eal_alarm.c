/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/timerfd.h>

#include <rte_memory.h>
#include <rte_interrupts.h>
#include <rte_alarm.h>
#include <rte_common.h>
#include <rte_per_lcore.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_spinlock.h>
#include <eal_private.h>

#ifndef    TFD_NONBLOCK
#include <fcntl.h>
#define    TFD_NONBLOCK    O_NONBLOCK
#endif

#define NS_PER_US 1000
#define US_PER_MS 1000
#define MS_PER_S 1000
#ifndef US_PER_S
#define US_PER_S (US_PER_MS * MS_PER_S)
#endif

#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif

struct alarm_entry {
    LIST_ENTRY(alarm_entry) next;
    struct timeval time;
    rte_eal_alarm_callback cb_fn;
    void *cb_arg;
    volatile uint8_t executing;
    volatile pthread_t executing_id;
};

static LIST_HEAD(alarm_list, alarm_entry) alarm_list = LIST_HEAD_INITIALIZER();
static rte_spinlock_t alarm_list_lk = RTE_SPINLOCK_INITIALIZER;

static struct rte_intr_handle intr_handle = {.fd = -1 };
static int handler_registered = 0;
static void eal_alarm_callback(void *arg);
/*  定时器初始化 */
int
rte_eal_alarm_init(void)
{
    intr_handle.type = RTE_INTR_HANDLE_ALARM;
    /* create a timerfd file descriptor */
    intr_handle.fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (intr_handle.fd == -1)
        goto error;

    return 0;

error:
    rte_errno = errno;
    return -1;
}
/* 定时器处理函数 */
static void
eal_alarm_callback(void *arg __rte_unused)
{
    struct timespec now;
    struct alarm_entry *ap;

    rte_spinlock_lock(&alarm_list_lk);
    while ((ap = LIST_FIRST(&alarm_list)) !=NULL && /* 遍历定时器 */
            clock_gettime(CLOCK_TYPE_ID, &now) == 0 && /* 获取当前时间 */
            (ap->time.tv_sec < now.tv_sec || (ap->time.tv_sec == now.tv_sec && /* 与当前时间比较 */
                        (ap->time.tv_usec * NS_PER_US) <= now.tv_nsec))) {
        ap->executing = 1; /* 设定定时器执行标志 */
        ap->executing_id = pthread_self(); /* 当前线程tid */
        rte_spinlock_unlock(&alarm_list_lk);

        ap->cb_fn(ap->cb_arg); /* 执行定时器处理函数 */

        rte_spinlock_lock(&alarm_list_lk);

        LIST_REMOVE(ap, next); /* 从定时器列表中删除 */
        free(ap);
    }
    /* 当定时器列表中还有待处理的定时器 */
    if (!LIST_EMPTY(&alarm_list)) {
        struct itimerspec atime = { .it_interval = { 0, 0 } };

        ap = LIST_FIRST(&alarm_list); /* 从列表中取出第一个定时器（因为是有序的定时器列表，所以后面的不再更新） */
        atime.it_value.tv_sec = ap->time.tv_sec;
        atime.it_value.tv_nsec = ap->time.tv_usec * NS_PER_US;
        /* perform borrow for subtraction if necessary */
        if (now.tv_nsec > (ap->time.tv_usec * NS_PER_US))
            atime.it_value.tv_sec--, atime.it_value.tv_nsec += US_PER_S * NS_PER_US;
        /* 更新定时器时间 */
        atime.it_value.tv_sec -= now.tv_sec;
        atime.it_value.tv_nsec -= now.tv_nsec;
        timerfd_settime(intr_handle.fd, 0, &atime, NULL); /* 重新设置定时器 */
    }
    rte_spinlock_unlock(&alarm_list_lk);
}
/* 安装定时器，将定时器插入到定时器列表(有序)中 */
int
rte_eal_alarm_set(uint64_t us, rte_eal_alarm_callback cb_fn, void *cb_arg)
{
    struct timespec now;
    int ret = 0;
    struct alarm_entry *ap, *new_alarm;

    /* Check parameters, including that us won't cause a uint64_t overflow */
    if (us < 1 || us > (UINT64_MAX - US_PER_S) || cb_fn == NULL)
        return -EINVAL;

    new_alarm = calloc(1, sizeof(*new_alarm));
    if (new_alarm == NULL)
        return -ENOMEM;

    /* use current time to calculate absolute time of alarm */
    clock_gettime(CLOCK_TYPE_ID, &now);

    new_alarm->cb_fn = cb_fn;
    new_alarm->cb_arg = cb_arg;
    new_alarm->time.tv_usec = ((now.tv_nsec / NS_PER_US) + us) % US_PER_S;
    new_alarm->time.tv_sec = now.tv_sec + (((now.tv_nsec / NS_PER_US) + us) / US_PER_S);

    rte_spinlock_lock(&alarm_list_lk);
    if (!handler_registered) {/* 若定时还没有注册，则先注册 */
        /* registration can fail, callback can be registered later */
        if (rte_intr_callback_register(&intr_handle, /* 中断注册接口 */
                eal_alarm_callback, NULL) == 0)
            handler_registered = 1;
    }

    if (LIST_EMPTY(&alarm_list)) /* 定时器列表为空，则直接在头部插入 */
        LIST_INSERT_HEAD(&alarm_list, new_alarm, next);
    else {
        LIST_FOREACH(ap, &alarm_list, next) { /* 根据时间，在定时器列表找到适当位置插入 */
            if (ap->time.tv_sec > new_alarm->time.tv_sec ||
                    (ap->time.tv_sec == new_alarm->time.tv_sec &&
                            ap->time.tv_usec > new_alarm->time.tv_usec)){
                LIST_INSERT_BEFORE(ap, new_alarm, next); /* 在ap元素前插入 */
                break;
            }
            if (LIST_NEXT(ap, next) == NULL) {
                LIST_INSERT_AFTER(ap, new_alarm, next); /* 在ap元素后插入 */
                break;
            }
        }
    }
    /* 如果当前的定时器列表只有一个(也是当前这个)，则开启定时器 
     * 后面开启的定时器就不需要开启定时器。
     */
    if (LIST_FIRST(&alarm_list) == new_alarm) { 
        struct itimerspec alarm_time = {
            .it_interval = {0, 0},
            .it_value = {
                .tv_sec = us / US_PER_S,
                .tv_nsec = (us % US_PER_S) * NS_PER_US,
            },
        };
        ret |= timerfd_settime(intr_handle.fd, 0, &alarm_time, NULL); /* 定时器开启 */
    }
    rte_spinlock_unlock(&alarm_list_lk);

    return ret;
}
/* 定时器取消 */
int
rte_eal_alarm_cancel(rte_eal_alarm_callback cb_fn, void *cb_arg)
{
    struct alarm_entry *ap, *ap_prev;
    int count = 0;
    int err = 0;
    int executing;

    if (!cb_fn) {
        rte_errno = EINVAL;
        return -1;
    }

    do {
        executing = 0;
        rte_spinlock_lock(&alarm_list_lk);
        /* remove any matches at the start of the list */
        while ((ap = LIST_FIRST(&alarm_list)) != NULL && /* 先查找第一个定时器 */
                cb_fn == ap->cb_fn && /* 根据callback和参数查找定时器 */
                (cb_arg == (void *)-1 || cb_arg == ap->cb_arg)) {

            if (ap->executing == 0) { /* 定时器不在执行 */
                LIST_REMOVE(ap, next); /* 直接从列表中删除就可以 */
                free(ap);
                count++;
            } else {
                /* If calling from other context, mark that alarm is executing
                 * so loop can spin till it finish. Otherwise we are trying to
                 * cancel our self - mark it by EINPROGRESS */
                if (pthread_equal(ap->executing_id, pthread_self()) == 0) /* 执行定时器和取消定时器不在同一个线程中，则等待定时器执行完成 */
                    executing++;
                else
                    err = EINPROGRESS;

                break;
            }
        }
        ap_prev = ap;

        /* now go through list, removing entries not at start */
        LIST_FOREACH(ap, &alarm_list, next) {/* 在列表中查找 */
            /* this won't be true first time through */
            if (cb_fn == ap->cb_fn &&
                    (cb_arg == (void *)-1 || cb_arg == ap->cb_arg)) {

                if (ap->executing == 0) {
                    LIST_REMOVE(ap, next);
                    free(ap);
                    count++;
                    ap = ap_prev;
                } else if (pthread_equal(ap->executing_id, pthread_self()) == 0)
                    executing++;
                else
                    err = EINPROGRESS;
            }
            ap_prev = ap;
        }
        rte_spinlock_unlock(&alarm_list_lk);
    } while (executing != 0); /* 有正在执行的定时器，则要继续等待 */

    if (count == 0 && err == 0)
        rte_errno = ENOENT;
    else if (err)
        rte_errno = err;

    return count;
}
