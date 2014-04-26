function arr = agg(file)
	f = fopen(file, 'r')
	fmt = '%f'
	size = [1 Inf]
	arr = fscanf(f, fmt, size)