global n = 5000000;

global a4 = 1.2.3.4;
global a6 = [ffee::1];


event zeek_init()
	{
	local i = n;
	local sum = 0;
	while ( i > 0 )
		{
		sum += |addr_to_counts(a4)| + |addr_to_counts(a6)|;
		sum += |decode_base64("dGVzdAo=")|;
		sum += double_to_count(2.0);
		sum += int_to_count(+32);
		sum += port_to_count(to_port("80/tcp"));
		sum += double_to_count(pow(2, 2));

		--i;
		}

	print sum;
	}
