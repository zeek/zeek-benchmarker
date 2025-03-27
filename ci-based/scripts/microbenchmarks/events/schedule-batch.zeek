# Schedule n times m events.
global n = 4000;
global m = 2000;

redef exit_only_after_terminate = T;

global sum = 0;

event e(c: count)
	{
	sum += c;
	}

event more(n: count)
	{
	if ( n == 0 )
		{
		terminate();
		return;

		}
	local i = 0;
	while ( ++i < m )
		schedule 0.1usec { e(i) };

	event more(n - 1);
	}

event zeek_init()
	{
	event more(n);
	}

event zeek_done()
	{
	print sum;
	}
