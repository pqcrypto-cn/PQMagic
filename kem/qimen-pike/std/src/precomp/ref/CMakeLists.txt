add_custom_target(precomp)
set_target_properties(precomp PROPERTIES EXCLUDE_FROM_ALL TRUE)

include(${SELECT_PIKE_VARIANT})