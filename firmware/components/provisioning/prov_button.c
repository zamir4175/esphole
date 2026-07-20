/*
 * prov_button — botón BOOT (GPIO0) para el factory reset (P12).
 * Nivel bajo = pulsado (pull-up interno). Confirma la pulsación mantenida por
 * muestreo: si en toda la ventana 'ms' el pin sigue bajo, cuenta como mantenida.
 */
#include "provisioning.h"

#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define BOOT_GPIO 0
#define SAMPLE_MS 50

bool prov_button_held_ms(uint32_t ms)
{
    static bool configurado = false;
    if (!configurado) {
        gpio_config_t io = {
            .pin_bit_mask = 1ULL << BOOT_GPIO,
            .mode = GPIO_MODE_INPUT,
            .pull_up_en = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };
        gpio_config(&io);
        configurado = true;
    }
    if (gpio_get_level(BOOT_GPIO) != 0) {
        return false; /* no está pulsado ahora mismo */
    }
    /* muestrea toda la ventana: cualquier suelta lo descarta */
    uint32_t transcurrido = 0;
    while (transcurrido < ms) {
        vTaskDelay(pdMS_TO_TICKS(SAMPLE_MS));
        transcurrido += SAMPLE_MS;
        if (gpio_get_level(BOOT_GPIO) != 0) {
            return false;
        }
    }
    return true;
}
