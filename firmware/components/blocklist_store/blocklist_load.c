/*
 * Carga de la lista de bloqueo desde su partición (T027).
 * Formato (tools/gen_blocklist.py): "EBL1" | count u32 LE | entradas
 * invertidas-normalizadas NUL-terminadas, YA ordenadas y podadas.
 * Fail-open total: cualquier problema deja la lista como esté (vacía o de
 * prueba) y el servicio sigue reenviando (FR-007/CB-20).
 */
#include "blocklist_load.h"

#include <string.h>

#include "esp_log.h"
#include "esp_partition.h"
#include "esp_timer.h"

static const char *TAG = "bl_load";

bool blocklist_load_from_partition(blocklist_t *bl)
{
    const esp_partition_t *part =
        esp_partition_find_first(0x40, 0x00, "blocklist");
    if (part == NULL) {
        ESP_LOGW(TAG, "sin partición 'blocklist'");
        return false;
    }
    const void *base = NULL;
    esp_partition_mmap_handle_t mh;
    if (esp_partition_mmap(part, 0, part->size, ESP_PARTITION_MMAP_DATA, &base,
                           &mh) != ESP_OK) {
        ESP_LOGW(TAG, "mmap de la partición falló");
        return false;
    }
    const uint8_t *d = base;
    if (memcmp(d, "EBL1", 4) != 0) {
        ESP_LOGW(TAG, "partición sin lista válida (magic)");
        esp_partition_munmap(mh);
        return false;
    }
    uint32_t count;
    memcpy(&count, d + 4, 4);

    int64_t t0 = esp_timer_get_time();
    const char *p = (const char *)d + 8;
    const char *fin = (const char *)d + part->size;
    uint32_t cargadas = 0;
    for (uint32_t i = 0; i < count && p < fin; i++) {
        size_t len = strnlen(p, (size_t)(fin - p));
        if (len == 0 || len > ESPHOLE_DOMAIN_MAX || p + len >= fin) {
            break; /* entrada corrupta: paramos aquí, lo cargado vale */
        }
        if (blocklist_add(bl, p, len)) {
            cargadas++;
        }
        p += len + 1;
    }
    blocklist_finalize(bl); /* pre-ordenada: verificación O(n), sin sort */
    esp_partition_munmap(mh);

    ESP_LOGI(TAG, "lista ACTIVA: %u dominios en %lld ms (truncados %u)",
             (unsigned)bl->count, (esp_timer_get_time() - t0) / 1000,
             (unsigned)bl->truncated);
    return bl->count > 0;
}

#define SECT 4096

bool blocklist_save_to_partition(const blocklist_t *bl)
{
    if (bl == NULL || bl->blob == NULL || bl->index == NULL ||
        bl->state != BL_ACTIVE) {
        return false;
    }
    const esp_partition_t *part =
        esp_partition_find_first(0x40, 0x00, "blocklist");
    if (part == NULL) {
        ESP_LOGW(TAG, "sin partición 'blocklist' para guardar");
        return false;
    }
    /* tamaño total del EBL1: cabecera + Σ(len+1) */
    size_t total = 8;
    for (uint32_t i = 0; i < bl->count; i++) {
        total += strlen(bl->blob + bl->index[i]) + 1;
    }
    if (total > part->size) {
        ESP_LOGE(TAG, "lista serializada (%u B) > partición (%u B)",
                 (unsigned)total, (unsigned)part->size);
        return false;
    }
    size_t erase = (total + SECT - 1) & ~((size_t)SECT - 1);
    if (erase > part->size) {
        erase = part->size;
    }
    if (esp_partition_erase_range(part, 0, erase) != ESP_OK) {
        ESP_LOGE(TAG, "erase de la partición falló");
        return false;
    }
    /* escritura en streaming con un buffer de sector (sin PSRAM extra) */
    static uint8_t sect[SECT];
    size_t off = 0, b = 0;
    memcpy(sect, "EBL1", 4);
    uint32_t c = bl->count;
    sect[4] = (uint8_t)c;
    sect[5] = (uint8_t)(c >> 8);
    sect[6] = (uint8_t)(c >> 16);
    sect[7] = (uint8_t)(c >> 24);
    b = 8;
    for (uint32_t i = 0; i < bl->count; i++) {
        const char *e = bl->blob + bl->index[i];
        size_t l = strlen(e) + 1; /* incluye el NUL */
        size_t pos = 0;
        while (pos < l) {
            size_t space = SECT - b;
            size_t take = (l - pos < space) ? (l - pos) : space;
            memcpy(sect + b, e + pos, take);
            b += take;
            pos += take;
            if (b == SECT) {
                if (esp_partition_write(part, off, sect, SECT) != ESP_OK) {
                    ESP_LOGE(TAG, "write de la partición falló");
                    return false;
                }
                off += SECT;
                b = 0;
            }
        }
    }
    if (b > 0) {
        while (b % 4 != 0) {
            sect[b++] = 0xff; /* padding a 4 B (parser ignora tras 'count') */
        }
        if (esp_partition_write(part, off, sect, b) != ESP_OK) {
            ESP_LOGE(TAG, "write final de la partición falló");
            return false;
        }
    }
    ESP_LOGI(TAG, "lista persistida: %u dominios, %u B", (unsigned)bl->count,
             (unsigned)total);
    return true;
}

bool blocklist_reload_from_partition(blocklist_t *bl)
{
    blocklist_reset(bl);
    return blocklist_load_from_partition(bl);
}
