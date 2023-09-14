global n = 10000000;


global pat = /some(thing|one)/;

event zeek_init()
	{
	local i = n;
	local sum = 0;
	while ( i > 0 )
		{
		if ( pat in "something" )
			sum += 1;

		if ( pat in "somewhere" )
			sum += 1;
		--i;
		}
	print sum;
	}
