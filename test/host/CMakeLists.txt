# Arnés de tests en host para los módulos PUROS (research.md R3).
# Unity se toma del árbol de ESP-IDF ya instalado: sin dependencia de red.
cmake_minimum_required(VERSION 3.16)
project(esphole_host_tests C)

enable_testing()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT DEFINED IDF_PATH)
  if(DEFINED ENV{IDF_PATH})
    set(IDF_PATH $ENV{IDF_PATH})
  else()
    set(IDF_PATH $ENV{HOME}/.espressif/v6.0.1/esp-idf)
  endif()
endif()
set(UNITY_SRC ${IDF_PATH}/components/unity/unity/src)
if(NOT EXISTS ${UNITY_SRC}/unity.c)
  message(FATAL_ERROR "Unity no encontrado en ${UNITY_SRC}; exporta IDF_PATH o pasa -DIDF_PATH=...")
endif()

# La entrada de red es hostil: todo test corre con ASan+UBSan (Principio V, CB-40).
set(SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -g)
set(WARN_FLAGS -Wall -Wextra -Werror)

add_library(unity STATIC ${UNITY_SRC}/unity.c)
target_include_directories(unity PUBLIC ${UNITY_SRC})
target_compile_options(unity PRIVATE ${SAN_FLAGS})

set(COMPONENTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../firmware/components)

# add_host_test(<nombre> <fuentes...>): fuentes = el test + los .c de los módulos
# puros bajo prueba (se compilan tal cual, sin build de IDF).
function(add_host_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE unity)
  target_compile_options(${name} PRIVATE ${WARN_FLAGS} ${SAN_FLAGS})
  target_link_options(${name} PRIVATE ${SAN_FLAGS})
  file(GLOB _incs ${COMPONENTS_DIR}/*/include)
  target_include_directories(${name} PRIVATE ${_incs})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

# add_host_bench(<nombre> <fuentes...>): como add_host_test pero -O2 y sin
# sanitizers — mide tiempos reales, no instrumentados.
function(add_host_bench name)
  add_executable(${name} ${ARGN})
  target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -O2)
  file(GLOB _incs ${COMPONENTS_DIR}/*/include)
  target_include_directories(${name} PRIVATE ${_incs})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

add_host_test(test_smoke test_smoke.c)
add_host_test(test_domain test_domain.c ${COMPONENTS_DIR}/domain/domain.c)
add_host_test(test_dns_wire_parse test_dns_wire_parse.c ${COMPONENTS_DIR}/dns_wire/dns_wire.c)
add_host_test(test_dns_wire_build test_dns_wire_build.c ${COMPONENTS_DIR}/dns_wire/dns_wire.c)
add_host_test(test_blocklist test_blocklist.c ${COMPONENTS_DIR}/blocklist/blocklist.c)
add_host_bench(bench_blocklist bench_blocklist.c ${COMPONENTS_DIR}/blocklist/blocklist.c)
add_host_test(test_cache test_cache.c ${COMPONENTS_DIR}/cache/cache.c ${COMPONENTS_DIR}/dns_wire/dns_wire.c)
add_host_test(test_ratelimit test_ratelimit.c ${COMPONENTS_DIR}/ratelimit/ratelimit.c)
add_host_test(test_policy test_policy.c ${COMPONENTS_DIR}/policy/policy.c)
add_host_test(test_pending test_pending.c ${COMPONENTS_DIR}/upstream/pending.c ${COMPONENTS_DIR}/dns_wire/dns_wire.c)
add_host_test(test_metrics test_metrics.c ${COMPONENTS_DIR}/metrics/metrics.c)
add_host_test(test_provision_logic test_provision_logic.c ${COMPONENTS_DIR}/provision_logic/provision_logic.c)
add_host_test(test_webapi_logic test_webapi_logic.c ${COMPONENTS_DIR}/webapi_logic/webapi_logic.c)
add_host_test(test_hostlist test_hostlist.c ${COMPONENTS_DIR}/hostlist/hostlist.c)
add_host_test(test_dhcp_wire test_dhcp_wire.c ${COMPONENTS_DIR}/dhcp_wire/dhcp_wire.c)
add_host_test(test_dhcp_lease test_dhcp_lease.c ${COMPONENTS_DIR}/dhcp_lease/dhcp_lease.c)
add_host_test(test_dot_frame test_dot_frame.c ${COMPONENTS_DIR}/dot_frame/dot_frame.c)
add_host_test(test_clients test_clients.c ${COMPONENTS_DIR}/clients/clients.c)
