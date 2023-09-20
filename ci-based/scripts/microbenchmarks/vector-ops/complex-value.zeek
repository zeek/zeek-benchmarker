type V: record {
	c1: count;
	c2: count;
};

global n = 10000000;

global vec: vector of V;

event zeek_init()
	{
	while ( |vec| < n )
		{
		vec += V($c1=|vec|,$c2=|vec|);
		}

	local sum = 0;
	for ( i in vec )
		sum += vec[i]$c1 + vec[i]$c2;

	print sum;
	}
