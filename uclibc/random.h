struct uclibc_random_data {
    int32_t *fptr;  /* Front pointer.  */
    int32_t *rptr;  /* Rear pointer.  */
    int32_t *state; /* Array of state values.  */
#if 0
    int rand_type;		/* Type of random number generator.  */
    int rand_deg;		/* Degree of random number generator.  */
    int rand_sep;		/* Distance between front and rear.  */
#else
    /* random_r.c, TYPE_x, DEG_x, SEP_x - small enough for int8_t */
    int8_t rand_type; /* Type of random number generator.  */
    int8_t rand_deg;  /* Degree of random number generator.  */
    int8_t rand_sep;  /* Distance between front and rear.  */
#endif
    int32_t *end_ptr; /* Pointer behind state table.  */
};

void uclibc_srandom(unsigned int x);
long int uclibc_random(void);

int uclibc_srandom_r(unsigned int seed, struct uclibc_random_data *buf);
int uclibc_random_r(struct uclibc_random_data *buf, int32_t *result);
