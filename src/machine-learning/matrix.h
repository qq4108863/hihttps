/*-
* Copyright (c) 2012 Hamrouni Ghassen.
*
*  2013-02  Modified for dynamic resizing by Ahmed Ben Romdhane
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

/************************************************************************/
/*          Sparse matrix data structure (Yale format)                  */
/************************************************************************/

#ifndef SPARSE_MATRIX_H
#define SPARSE_MATRIX_H

#include <stddef.h>

/* Coordinate list (COO) */
typedef struct coo_entry
{
	float		value;
	size_t		row_i;
	size_t		column_j;
} coo_entry_t;

/* coo_matrix is used to initialize a sparse matrix */
typedef struct coo_matrix
{
	coo_entry_t*	entries;
	size_t		current_size;
	size_t		size;
} coo_matrix_t;

/* Allocate space for a COO matrix */
coo_matrix_t*
init_coo_matrix(size_t max_size);

/* delete the COO matrix */ 
void
free_coo_matrix(coo_matrix_t* matrix);

/* insert an element into the COO matrix */
void
insert_coo_matrix(float val, size_t row_i, size_t column_j, coo_matrix_t* matrix);

/* sort the COO matrix left-to-right top-to-bottom (row-major) order */
void
sort_coo_matrix(coo_matrix_t* matrix);

/* Sparse matrix structure (yale format) */
typedef struct sparse_matrix
{
	size_t			column_nb;

	size_t			row_nb;

	size_t			nonzero_entries_nb; /* NNZ */

	float*			values;             /* A */

	size_t*			row_index;          /* IA */

	size_t*			column_index;       /* JA */

	size_t			row_capacity;

	size_t			nonzero_entries_capacity;

} sparse_matrix_t;

/* Allocate space for the sparse matrix */
sparse_matrix_t* 
init_sparse_matrix(coo_matrix_t* c_matrix, size_t row_nb, size_t column_nb);

/* Delete the sparse matrix */
void
free_sparse_matrix(sparse_matrix_t* matrix);

/* Check the matrix contains an element */
int
element_exists(size_t row_i, size_t column_j, sparse_matrix_t* matrix);

/* Get an element from the matrix */
float 
get_element(size_t row_i, size_t column_j, sparse_matrix_t* matrix);

/* Get the average of row i (sum of filled values / number of filled values) */
float
row_values_average(size_t row_i, sparse_matrix_t* matrix);

/* Get the average of column j (sum of filled values / number of filled values) */
float
column_values_average(size_t column_j, sparse_matrix_t* matrix);

/* Add a row to the sparse matrix */
void add_row(sparse_matrix_t* input_matrix);

/* Add a column to the sparse matrix */
void add_column(sparse_matrix_t* input_matrix);

/* Add a number of rows to the sparse matrix */
void add_rows (sparse_matrix_t* input_matrix , size_t number);

/* Add a list of values in the COO to the sparse matrix */
void insert_coo (sparse_matrix_t* input_matrix, coo_matrix_t* c_matrix);

/* Inset a value to the sparse matrix */
void insert_value (sparse_matrix_t* input_matrix, size_t row, size_t col, float val );

/* Get a row from the sparse matrix */
double* 
get_row(size_t row_i, sparse_matrix_t* matrix);

/* Get number of elements in a row*/
int 
get_number_in_row(size_t row_i, sparse_matrix_t* matrix);

/* Get number of elements in a column*/
int 
get_number_in_column(size_t column_j, sparse_matrix_t* matrix);

/*append coo into another coo*/
void 
insert_coo_to_coo (coo_matrix_t* input_matrix, coo_matrix_t* c_matrix);

/*check if element already exists in the coo or not*/
int 
coo_element_exist(size_t row_i,size_t column_j,coo_matrix_t* c_matrix);

/*get a row from a sparse matrix in a coo_matrix*/
coo_matrix_t*
get_row_in_coo(sparse_matrix_t* sparse_matrix,size_t row_i);
#endif /* SPARSE_MATRIX_H */

