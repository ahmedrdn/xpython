#include <string.h>
#include "py/runtime.h"
#include "py/mpstate.h"

#define XWATCH_VERSION "0.1.0"
#define REPEAT_MS 50                // after the deadline, interrupt again every 50 ms
#define MAX_MS    600000

static volatile bool armed = false;
static volatile bool fired = false;

// Raise KeyboardInterrupt in the running Python code (safe from timers and signals)
static void fire(void) {
    fired = true;
    mp_sched_keyboard_interrupt();
}

#if defined(ESP_PLATFORM) || __has_include("esp_random.h")
// ---------- ESP32: an esp_timer ----------
#include "esp_timer.h"
static esp_timer_handle_t timer = NULL;

static void on_timer(void *arg) {
    (void)arg;
    if (!armed) {
        return;
    }
    fire();
    esp_timer_start_once(timer, REPEAT_MS * 1000);      // keep going until disarmed
}
static void timer_start(uint32_t ms) {
    if (timer == NULL) {
        const esp_timer_create_args_t args = { .callback = on_timer, .name = "xwatch" };
        esp_timer_create(&args, &timer);
    }
    esp_timer_stop(timer);
    esp_timer_start_once(timer, (uint64_t)ms * 1000);
}
static void timer_stop(void) {
    if (timer != NULL) {
        esp_timer_stop(timer);
    }
}
#elif defined(__unix__)
// ---------- PC: a SIGALRM interval timer ----------
#include <signal.h>
#include <sys/time.h>
static void on_alarm(int sig) {
    (void)sig;
    if (armed) {
        fire();
    }
}
static void timer_start(uint32_t ms) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval t;
    t.it_value.tv_sec = ms / 1000;
    t.it_value.tv_usec = (ms % 1000) * 1000;
    t.it_interval.tv_sec = 0;
    t.it_interval.tv_usec = REPEAT_MS * 1000;
    setitimer(ITIMER_REAL, &t, NULL);
}
static void timer_stop(void) {
    struct itimerval t;
    memset(&t, 0, sizeof(t));
    setitimer(ITIMER_REAL, &t, NULL);
}
#else
#error "xwatch: no timer for this port yet"
#endif

// ---------- Python functions ----------
static mp_obj_t xwatch_version(void) {
    return mp_obj_new_str(XWATCH_VERSION, strlen(XWATCH_VERSION));
}
static MP_DEFINE_CONST_FUN_OBJ_0(xwatch_version_obj, xwatch_version);

// arm(ms): interrupt the running code after ms milliseconds
static mp_obj_t xwatch_arm(mp_obj_t ms_in) {
    mp_int_t ms = mp_obj_get_int(ms_in);
    if (ms < 1 || ms > MAX_MS) {
        mp_raise_ValueError(MP_ERROR_TEXT("ms must be 1..600000"));
    }
    fired = false;
    armed = true;
    timer_start((uint32_t)ms);
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(xwatch_arm_obj, xwatch_arm);

// disarm() -> True if the time limit was reached
static mp_obj_t xwatch_disarm(void) {
    armed = false;
    timer_stop();
    // Drop a timeout interrupt that was scheduled but not raised yet
    if (MP_STATE_MAIN_THREAD(mp_pending_exception) == MP_OBJ_FROM_PTR(&MP_STATE_VM(mp_kbd_exception))) {
        MP_STATE_MAIN_THREAD(mp_pending_exception) = MP_OBJ_NULL;
    }
    return mp_obj_new_bool(fired);
}
static MP_DEFINE_CONST_FUN_OBJ_0(xwatch_disarm_obj, xwatch_disarm);

// fired() -> True if the last time limit was reached
static mp_obj_t xwatch_fired(void) {
    return mp_obj_new_bool(fired);
}
static MP_DEFINE_CONST_FUN_OBJ_0(xwatch_fired_obj, xwatch_fired);

static const mp_rom_map_elem_t xwatch_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_xwatch) },
    { MP_ROM_QSTR(MP_QSTR_version),  MP_ROM_PTR(&xwatch_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_arm),      MP_ROM_PTR(&xwatch_arm_obj) },
    { MP_ROM_QSTR(MP_QSTR_disarm),   MP_ROM_PTR(&xwatch_disarm_obj) },
    { MP_ROM_QSTR(MP_QSTR_fired),    MP_ROM_PTR(&xwatch_fired_obj) },
};
static MP_DEFINE_CONST_DICT(xwatch_globals, xwatch_globals_table);

const mp_obj_module_t xwatch_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&xwatch_globals,
};
MP_REGISTER_MODULE(MP_QSTR_xwatch, xwatch_module);