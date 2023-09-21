global n = 4000000;

type K: record {
	c: count;
	s: string;
};

global k1 = K($c=42, $s="42");
global k2 = K($c=43, $s="43");
global k3 = K($c=44, $s="44");

global tbl: table[K] of count = {
	[k1] = 1,
};

event zeek_init()
	{
	local i = n;
	local sum = 0;
	while ( i > 0 )
		{
		sum += tbl[k1];
		sum += |tbl|;
		sum += k1 in tbl ? 1 : 0;

		tbl[k2] = 2;

		sum += tbl[k2];
		sum += |tbl|;
		sum += k2 in tbl ? 1 : 0;
		sum += k3 in tbl ? 1 : 0;

		delete tbl[k2];
		delete tbl[k3];

		sum += |tbl|;
		--i;
		}
	}
