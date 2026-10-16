/*
 * SPDX-License-Identifier: MIT
 */
/*
 * ZMK's HID service requires an encrypted link, but when encryption fails
 * (stale or missing keys on either side) ZMK only logs it. The link stays up,
 * the host shows the keyboard as connected, every report is rejected, and
 * because the profile counts as connected ZMK never advertises again.
 *
 * This asks a bonded host to encrypt as soon as it connects, instead of
 * waiting for the first keypress, and drops any link whose encryption fails
 * or never completes. ZMK then advertises again and the host reconnects or
 * re-pairs on its own.
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(alu40_ble_recovery, CONFIG_ZMK_LOG_LEVEL);

struct recovery_slot {
    struct k_work_delayable work;
    bt_addr_le_t peer;
    bool kick;
};

static struct recovery_slot slots[CONFIG_BT_MAX_CONN];
static atomic_t consecutive_kicks;

static void match_bond(const struct bt_bond_info *info, void *user_data) {
    struct {
        const bt_addr_le_t *addr;
        bool found;
    } *search = user_data;

    if (bt_addr_le_cmp(&info->addr, search->addr) == 0) {
        search->found = true;
    }
}

static bool is_bonded(const bt_addr_le_t *addr) {
    struct {
        const bt_addr_le_t *addr;
        bool found;
    } search = {.addr = addr, .found = false};

    bt_foreach_bond(BT_ID_DEFAULT, match_bond, &search);
    return search.found;
}

static bool is_peripheral(struct bt_conn *conn) {
    struct bt_conn_info info;

    return bt_conn_get_info(conn, &info) == 0 && info.role == BT_CONN_ROLE_PERIPHERAL;
}

static void recovery_work_handler(struct k_work *work) {
    struct k_work_delayable *dwork = k_work_delayable_from_work(work);
    struct recovery_slot *slot = CONTAINER_OF(dwork, struct recovery_slot, work);
    char addr[BT_ADDR_LE_STR_LEN];

    // Look the link up again rather than holding a reference, so a link that
    // already went away is simply skipped.
    struct bt_conn *conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, &slot->peer);
    if (conn == NULL) {
        return;
    }

    bt_addr_le_to_str(&slot->peer, addr, sizeof(addr));

    if (!slot->kick && bt_conn_get_security(conn) >= BT_SECURITY_L2) {
        bt_conn_unref(conn);
        return;
    }

    if (atomic_get(&consecutive_kicks) >= CONFIG_ALU40_BLE_RECOVERY_MAX_RETRIES) {
        LOG_WRN("Leaving unencrypted link to %s up, retry limit reached", addr);
        bt_conn_unref(conn);
        return;
    }

    atomic_inc(&consecutive_kicks);
    LOG_WRN("Link to %s is not encrypted, disconnecting so the host can reconnect", addr);

    int err = bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
    if (err) {
        LOG_ERR("Failed to disconnect %s (err %d)", addr, err);
    }

    bt_conn_unref(conn);
}

static void connected(struct bt_conn *conn, uint8_t err) {
    if (err || !is_peripheral(conn)) {
        return;
    }

    struct recovery_slot *slot = &slots[bt_conn_index(conn)];
    const bt_addr_le_t *dst = bt_conn_get_dst(conn);

    bt_addr_le_copy(&slot->peer, dst);
    slot->kick = false;

    // A host pairing for the first time encrypts as part of pairing, and a
    // failed pairing is handled in security_changed.
    if (!is_bonded(dst)) {
        return;
    }

    int sec_err = bt_conn_set_security(conn, BT_SECURITY_L2);
    if (sec_err) {
        LOG_DBG("Security request on connect failed (err %d)", sec_err);
    }

    k_work_reschedule(&slot->work, K_MSEC(CONFIG_ALU40_BLE_RECOVERY_TIMEOUT_MS));
}

static void disconnected(struct bt_conn *conn, uint8_t reason) {
    if (!is_peripheral(conn)) {
        return;
    }

    k_work_cancel_delayable(&slots[bt_conn_index(conn)].work);
}

static void security_changed(struct bt_conn *conn, bt_security_t level,
                             enum bt_security_err err) {
    if (!is_peripheral(conn)) {
        return;
    }

    struct recovery_slot *slot = &slots[bt_conn_index(conn)];

    if (!err && level >= BT_SECURITY_L2) {
        atomic_clear(&consecutive_kicks);
        k_work_cancel_delayable(&slot->work);
        return;
    }

    if (err) {
        // Disconnecting from inside a host callback is deferred to the
        // workqueue.
        bt_addr_le_copy(&slot->peer, bt_conn_get_dst(conn));
        slot->kick = true;
        k_work_reschedule(&slot->work, K_NO_WAIT);
    }
}

BT_CONN_CB_DEFINE(alu40_ble_recovery_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
    .security_changed = security_changed,
};

static int alu40_ble_recovery_init(void) {
    for (int i = 0; i < ARRAY_SIZE(slots); i++) {
        k_work_init_delayable(&slots[i].work, recovery_work_handler);
    }

    return 0;
}

SYS_INIT(alu40_ble_recovery_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
