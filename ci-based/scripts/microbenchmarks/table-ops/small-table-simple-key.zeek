global n = 4000000;

global k1 = 1;
global k2 = 2;
global k3 = 3;

global tbl: table[count] of count = {
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
