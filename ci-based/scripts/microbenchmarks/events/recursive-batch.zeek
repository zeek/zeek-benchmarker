# Queue n times m events.
global n = 5000;
global m = 3000;

redef exit_only_after_terminate = T;

global sum = 0;

event e(n: count) {
	sum += n;
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
		event e(i);

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
