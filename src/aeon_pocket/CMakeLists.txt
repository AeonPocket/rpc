set(aeon_pocket_sources
  main.cpp)

set(aeon_pocket_headers)

#set(aeon_pocket_private_headers
#  simplewallet.h)

monero_private_headers(aeon_pocket
  ${aeon_pocket_private_headers})
monero_add_executable(aeon_pocket
  ${aeon_pocket_sources}
  ${aeon_pocket_headers}
  ${saeon_pocket_private_headers})
target_link_libraries(aeon_pocket
  PRIVATE
    wallet
    rpc_base
    cryptonote_core
    cncrypto
    common
    mnemonics
    epee
    ${EPEE_READLINE}
    version
    ${Boost_CHRONO_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${ICU_LIBRARIES}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${GNU_READLINE_LIBRARY}
    ${EXTRA_LIBRARIES})
set_property(TARGET aeon_pocket
  PROPERTY
    OUTPUT_NAME "aeon_pocket")
install(TARGETS aeon_pocket DESTINATION bin)