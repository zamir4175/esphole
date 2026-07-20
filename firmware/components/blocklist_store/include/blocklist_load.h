#ifndef ESPHOLE_BLOCKLIST_LOAD_H
#define ESPHOLE_BLOCKLIST_LOAD_H

#include "blocklist.h"

/* Carga la lista desde la partición 'blocklist' (mmap). false si no hay
 * partición o lista válida — el llamador decide el fallback. */
bool blocklist_load_from_partition(blocklist_t *bl);

/*
 * Persiste la lista finalizada a la partición 'blocklist' en formato EBL1
 * (spec 004). Serializa en streaming con un buffer de 4 KB (no requiere PSRAM
 * extra): calcula el tamaño, borra el tramo necesario y escribe. La partición
 * solo se sobrescribe aquí, tras un build exitoso (atomicidad, FR-007).
 * false si no hay partición, la lista no está ACTIVE, o no cabe.
 */
bool blocklist_save_to_partition(const blocklist_t *bl);

/* Recuperación: reset + recarga desde la partición (lista previa intacta).
 * Para el camino de fallo de la actualización (spec 004). */
bool blocklist_reload_from_partition(blocklist_t *bl);

#endif /* ESPHOLE_BLOCKLIST_LOAD_H */
