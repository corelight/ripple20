@load ./config

# @if (Cluster::is_enabled())
	# @load ./ripple20_CLUSTERIZED
# @else
	@load ./ripple20_nonclusterized
# @endif
