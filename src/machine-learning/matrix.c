#include "matrix.h"

#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <assert.h>
#include <stdio.h>
coo_matrix_t*
init_coo_matrix(size_t max_size)
{
	coo_matrix_t* matrix = malloc(sizeof(coo_matrix_t));

	if (!matrix)
		return NULL;

	matrix->current_size = 0;
	matrix->size = max_size;

	matrix->entries = malloc(sizeof(coo_entry_t) * max_size);

	return matrix;
}

void
free_coo_matrix(coo_matrix_t* matrix)
{
	if (!matrix)
		return;

	free(matrix->entries);
	free(matrix);
}

void
insert_coo_matrix(float val, size_t row_i, size_t column_j, coo_matrix_t* matrix)
{
	if (!matrix)
		return;

	assert(matrix->current_size < matrix->size);

	matrix->entries[matrix->current_size].row_i = row_i;
	matrix->entries[matrix->current_size].column_j = column_j; 
	matrix->entries[matrix->current_size].value = val;

	matrix->current_size++;
}

int entry_cmp(const void *e1, const void *e2)
{
	coo_entry_t* entry1 = (coo_entry_t*) e1;
	coo_entry_t* entry2 = (coo_entry_t*) e2;

	assert(entry1 && entry2);

	if (!entry1 || !entry2) /* just to make the static analyzer happy ! */
		return 0;

	if (entry1->row_i > entry2->row_i)
		return 1;

	if (entry1->row_i < entry2->row_i)
		return -1;

	if (entry1->column_j > entry2->column_j)
		return 1;

	if (entry1->column_j < entry2->column_j)
		return -1;

	return 0;
}

void
sort_coo_matrix(coo_matrix_t* matrix)
{
	if (matrix)
		qsort(matrix->entries, matrix->size, sizeof(coo_entry_t), entry_cmp);
}

sparse_matrix_t* 
init_sparse_matrix(coo_matrix_t* c_matrix, size_t row_nb, size_t column_nb)
{
	size_t i;
	size_t current_row = 0;

	sparse_matrix_t* matrix = malloc(sizeof(sparse_matrix_t));

	assert(row_nb > 0 && column_nb > 0);

	if (!matrix)
		return NULL;

	matrix->column_nb = column_nb;
	matrix->row_nb = row_nb;
	matrix->nonzero_entries_nb = c_matrix->size;

	
	matrix->row_capacity = row_nb * 2;
	matrix->nonzero_entries_capacity = c_matrix->size * 2;

	matrix->values = malloc(sizeof(float) * c_matrix->size * 2);
	matrix->row_index = malloc(sizeof(size_t) * (row_nb + 1) * 2);
	matrix->column_index = malloc(sizeof(size_t) * c_matrix->size * 2);

	if (matrix->row_index)
	{
		for (i = 0; i < row_nb + 1; i++)
			matrix->row_index[i] = 0;
	}

	for (i = 0; i < c_matrix->size; i++)
	{
		if (current_row != (c_matrix->entries[i].row_i + 1))
		{
			if (c_matrix->entries[i].row_i < row_nb + 1)
			{
				if (matrix->row_index)
					matrix->row_index[c_matrix->entries[i].row_i] = i + 1;

				current_row = c_matrix->entries[i].row_i + 1;
			}
		} else if (i == (c_matrix->size - 1))
		{
			if (c_matrix->entries[i].row_i == row_nb - 1)
				if (matrix->row_index)
					matrix->row_index[row_nb] = i + 2;
		}

		if (matrix->values)
			matrix->values[i] = c_matrix->entries[i].value;

		if (matrix->column_index)
			matrix->column_index[i] = c_matrix->entries[i].column_j;
	}
	if (matrix->row_index)
	{
		for (i = 0; i < row_nb + 1; i++)
			if(matrix->row_index[i]==0)
			matrix->row_index[i] = matrix->row_index[i-1];
	}
	return matrix;
}

void
free_sparse_matrix(sparse_matrix_t* matrix)
{
	free(matrix->column_index);
	free(matrix->row_index);
	free(matrix->values);
	free(matrix);
}

int
element_exists(size_t row_i, size_t column_j, sparse_matrix_t* matrix)
{
	size_t i = 0;
	size_t r1, r2;
	r1 = r2 = 0; /* Range */

	assert(row_i < matrix->row_nb);
	assert(column_j < matrix->column_nb);

	if (!matrix->row_index[row_i]) return 0;

	r1 = matrix->row_index[row_i] - 1;
	r2 = matrix->row_index[row_i + 1] - 1;

	for (i = r1; i < r2; i++)
		if (matrix->column_index[i] == column_j)
			return 1;

	return 0;
}

float 
get_element(size_t row_i, size_t column_j, sparse_matrix_t* matrix)
{
	size_t i = 0;
	size_t r1, r2; /* Range */

	assert(row_i < matrix->row_nb);
	assert(column_j < matrix->column_nb);

	if (!matrix->row_index[row_i]) return 0;

	r1 = matrix->row_index[row_i] - 1;
	r2 = matrix->row_index[row_i + 1] - 1;

	for (i = r1; i < r2; i++)
		if (matrix->column_index[i] == column_j)
			return matrix->values[i];

	return 0;
}



float
row_values_average(size_t row_i, sparse_matrix_t* matrix)
{
	ptrdiff_t i = 0;
	ptrdiff_t r1, r2; /* Range */

	float sum = 0;
	size_t N = 0;

	if (!matrix->row_index[row_i]) return 0;

	r1 = matrix->row_index[row_i] - 1;
	r2 = matrix->row_index[row_i + 1] - 1;

	if (r1 >= 0)
	for (i = r1; i < r2; i++)
	{
		N++;
		sum += matrix->values[i];
	}

	if (N == 0)
		return 0.0f;

	return sum / ((float) N);
}

float
column_values_average(size_t column_j, sparse_matrix_t* matrix)
{
	size_t i = 0;

	float sum = 0;
	size_t N = 0;

	for (i = 0; i < matrix->nonzero_entries_nb; i++)
	{
		if ( matrix->column_index[i] == column_j)
		{
			N++;
			sum += matrix->values[i];
		}
	}

	if (N == 0)
		return 0.0f;

	return sum / ((float) N);
}

void
add_row ( sparse_matrix_t* input_matrix )
{
	size_t* new_row_index = NULL;

	if ( input_matrix->row_nb >= input_matrix->row_capacity )
	{
		input_matrix->row_capacity *= 2;
		new_row_index = realloc ( input_matrix->row_index,
			sizeof ( size_t ) * input_matrix->nonzero_entries_capacity );

		if (new_row_index)
		{
			input_matrix->row_index = new_row_index;
		}
	}

	input_matrix->row_nb ++;

	if (input_matrix->row_index)
	{
		input_matrix->row_index[input_matrix->row_nb] = input_matrix->row_index[input_matrix->row_nb - 1];
	}
}

void
add_column (sparse_matrix_t* input_matrix)
{
	input_matrix->column_nb ++;
}

void insert_value (sparse_matrix_t* input_matrix, size_t row, size_t col, float val )
{
	size_t i;
	size_t* new_column_index = NULL;
	float* new_values = NULL;

	size_t pos = input_matrix->row_index[row + 1] - 1;
	assert( (row < input_matrix->row_nb) && (col < input_matrix->column_nb) );
	
	if ( input_matrix->nonzero_entries_nb >= input_matrix->nonzero_entries_capacity )
	{
		input_matrix->nonzero_entries_capacity = input_matrix->nonzero_entries_capacity * 2;

		new_values = realloc ( input_matrix->values,
			sizeof ( float ) * ( input_matrix->nonzero_entries_capacity ) );

		if (new_values)
		{
			input_matrix->values = new_values;
		}
		
		new_column_index = realloc ( input_matrix->column_index ,
			sizeof ( size_t ) * ( input_matrix->nonzero_entries_capacity ) );

		if (new_column_index)
		{
			input_matrix->column_index = new_column_index;
		}
	}

	/* Shift the array input_matrix->values to the right after pos */
	memcpy ( &(input_matrix->values[pos + 1]) , &(input_matrix->values[pos]) ,
	         sizeof ( float ) * ( input_matrix->nonzero_entries_nb - ( pos ) ) );
	input_matrix->values[pos] = val;

	/* Shift the array input_matrix->column_index to the right after pos */
	memcpy ( &input_matrix->column_index[pos + 1], &input_matrix->column_index[pos] ,
	         sizeof ( size_t ) * ( input_matrix->nonzero_entries_nb - pos ) );
	input_matrix->column_index[pos] = col;

	if ( input_matrix->row_index[row] > pos + 1 )
	{
		input_matrix->row_index[row] = pos + 1;
	}
	for ( i = row + 1 ; i < input_matrix->row_nb + 1 ; i++ )
	{
		input_matrix->row_index[i]++;
	}

	input_matrix->nonzero_entries_nb++;
}


void add_rows (sparse_matrix_t* input_matrix , size_t number)
{
	size_t i;
	size_t* new_row_index = NULL;

	if ( (input_matrix->row_nb + number) >= input_matrix->row_capacity )
	{
		input_matrix->row_capacity += number;
		new_row_index =  realloc ( input_matrix->row_index,
			sizeof ( size_t ) * input_matrix ->nonzero_entries_capacity);

		if (new_row_index)
		{
			input_matrix->row_index = new_row_index;
		}
	}

	for (i = input_matrix->row_nb + 1; i < input_matrix->row_nb + number + 1; i++)
	{
		input_matrix->row_index[i] = input_matrix->row_index[i - 1];
	}

	input_matrix->row_nb += number;
}


void
add_columns (sparse_matrix_t* input_matrix, size_t number )
{
	input_matrix->column_nb += number;
}

void insert_coo (sparse_matrix_t* input_matrix, coo_matrix_t* c_matrix)
{
	size_t i, j;
	size_t pos;
	float* new_values = NULL;
	size_t* new_column_index = NULL;

	if ( input_matrix->nonzero_entries_nb + c_matrix->size >= input_matrix->nonzero_entries_capacity )
	{

		input_matrix->nonzero_entries_capacity *= 2;
		new_values = realloc ( input_matrix->values,
			sizeof ( float ) * ( input_matrix->nonzero_entries_capacity) );

		if (new_values)
		{
			input_matrix->values = new_values;
		}

		new_column_index = realloc ( input_matrix->column_index ,
			sizeof ( size_t ) * ( input_matrix->nonzero_entries_capacity) );

		if (new_column_index)
		{
			input_matrix->column_index = new_column_index;
		}
	}
	for (j = 0; j < c_matrix->size; j++)
	{
		pos = input_matrix->row_index[c_matrix->entries[j].row_i + 1] - 1;

		/* Shift the array input_matrix->values to the right after pos */
		memcpy ( &input_matrix->values[pos + 1] , &input_matrix->values[pos] ,
		         sizeof ( float ) * ( input_matrix->nonzero_entries_nb - ( pos ) ) );

		input_matrix->values[pos] = c_matrix->entries[j].value;

		/* Shift the array input_matrix->column_index to the right after pos */
		memcpy ( &input_matrix->column_index[pos + 1], &input_matrix->column_index[pos] ,
		         sizeof ( size_t ) * ( input_matrix->nonzero_entries_nb - pos ) );
		input_matrix->column_index[pos] = c_matrix->entries[j].column_j;

		if ( input_matrix->row_index[c_matrix->entries[j].row_i] > pos + 1)
		{
			input_matrix->row_index[c_matrix->entries[j].row_i] = pos;
		}
		for ( i = c_matrix->entries[j].row_i + 1 ; i < input_matrix->row_nb + 1 ; i++ )
		{
			input_matrix->row_index[i]++;
		}
		input_matrix->nonzero_entries_nb++;
	}
}

double* 
get_row(size_t row_i, sparse_matrix_t* matrix)
{
	size_t i = 0;
	size_t r1, r2; /* Range */
	double * vector=malloc(matrix->column_nb*sizeof(double));
	assert(row_i < matrix->row_nb);
	memset(vector,0,matrix->column_nb*sizeof(double));
	if (!matrix->row_index[row_i]) return 0;

	r1 = matrix->row_index[row_i] - 1;
	r2 = matrix->row_index[row_i + 1] - 1;

	for (i = r1; i < r2; i++)
		vector[matrix->column_index[i]] = matrix->values[i];

	return vector;
}

int 
get_number_in_row(size_t row_i, sparse_matrix_t* matrix)
{
	size_t r1, r2; /* Range */
	
	assert(row_i < matrix->row_nb);
	
	if (!matrix->row_index[row_i]) return 0;

	r1 = matrix->row_index[row_i] - 1;
	r2 = matrix->row_index[row_i + 1] - 1;


	return r2-r1;
}


int 
get_number_in_column(size_t column_j, sparse_matrix_t* matrix)
{
	size_t i,nb=0;
	for(i=0;i<matrix->nonzero_entries_nb;i++)
	{
		if(matrix->column_index[i]==column_j)
		{
		nb++;
		}
	}

	return nb;
}


void insert_coo_to_coo (coo_matrix_t* input_matrix, coo_matrix_t* c_matrix)
{
	size_t i;
	coo_entry_t* new_values = NULL;

	new_values = realloc(input_matrix->entries, sizeof(coo_entry_t)*(input_matrix->size + c_matrix->size));
	if (new_values)
	{
		input_matrix->entries = new_values;
		for(i = 0 ; i < c_matrix->size;i++)
		{
			input_matrix->entries[i + input_matrix->size].value=c_matrix->entries[i].value;
			input_matrix->entries[i + input_matrix->size].row_i=c_matrix->entries[i].row_i;
			input_matrix->entries[i + input_matrix->size].column_j=c_matrix->entries[i].column_j;
		}
		input_matrix->size = input_matrix->size + c_matrix->size;
	}
}



int coo_element_exist(size_t row_i,size_t column_j,coo_matrix_t* c_matrix)
{
	size_t i=0;
	if(c_matrix->current_size == 0)
	{
		return 0;
	}
	while ((i<c_matrix->current_size-1)&&((c_matrix->entries[i].column_j != column_j)||(c_matrix->entries[i].row_i!=row_i)))
	{
		i++;
	}
	
	return (c_matrix->entries[i].column_j == column_j)&&(c_matrix->entries[i].row_i == row_i);
}


coo_matrix_t* get_row_in_coo(sparse_matrix_t* sparse_matrix,size_t row_i)
{
	size_t i = 0;
	size_t r1,r2;
	coo_matrix_t* coo=init_coo_matrix(sparse_matrix->column_nb);
	assert(row_i < sparse_matrix->row_nb);

	if (!sparse_matrix->row_index[row_i]) return 0;

	r1 = sparse_matrix->row_index[row_i] - 1;
	r2 = sparse_matrix->row_index[row_i + 1] - 1;

	for (i = r1; i < r2; i++)
		insert_coo_matrix(sparse_matrix->values[i],row_i,sparse_matrix->column_index[i],coo);

	return coo;
}
