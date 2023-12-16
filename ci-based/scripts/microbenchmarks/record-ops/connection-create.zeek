global n = 5000000;

global ts = double_to_time(42.0);
global history = "ShADafF";
global uid = "C23890741";

event zeek_init()
	{
	local i = 0;
	local s = 0;
	while ( i < n )
		{
		local c: connection = connection(
			$start_time=ts,
			$duration=1sec,
			$history=history,
			$uid=uid,
		);
		c$orig = endpoint($size=i, $state=TCP_CLOSED, $flow_label=0);
		c$resp = endpoint($size=i*2, $state=TCP_CLOSED, $flow_label=0);
		c$tunnel = vector();

		s += c$orig$size;
		s += c$resp$size;
		s += |c$service|;
		s += |c$tunnel|;

		++i;
		}

	print i, s;
	}
