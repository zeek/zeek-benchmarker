global n = 30000000;

global vec: vector of count;

event zeek_init()
	{
	while ( |vec| < n )
		{
		vec += |vec|;
		}

	local sum = 0;
	for ( i in vec )
		sum += vec[i];

	print sum;
	}
