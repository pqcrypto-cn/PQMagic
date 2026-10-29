#include <quaternion.h>

void
ibz_mat_2x2_print(const ibz_mat_2x2_t *mat)
{
    ibz_printf("matrix: ");
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            ibz_printf("%Zd ", &((*mat)[i][j]));
        }
        ibz_printf("\n        ");
    }
    ibz_printf("\n");
}

void
ibz_mat_4x4_print(const ibz_mat_4x4_t *mat)
{
    ibz_printf("matrix: ");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_printf("%Zd ", &((*mat)[i][j]));
        }
        ibz_printf("\n        ");
    }
    ibz_printf("\n");
}

void
ibz_mat_4x5_print(const ibz_mat_4x5_t *mat)
{
    ibz_printf("matrix: ");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 5; j++) {
            ibz_printf("%Zd ", &((*mat)[i][j]));
        }
        ibz_printf("\n        ");
    }
    ibz_printf("\n");
}

void
ibz_mat_4x8_print(const ibz_mat_4x8_t *mat)
{
    ibz_printf("matrix: ");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            ibz_printf("%Zd ", &((*mat)[i][j]));
        }
        ibz_printf("\n        ");
    }
    ibz_printf("\n");
}

void
ibz_mat_print(int rows, int cols, const ibz_t mat[rows][cols])
{
    ibz_printf("matrix: ");
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            ibz_printf("%Zd ", &mat[i][j]);
        }
        ibz_printf("\n        ");
    }
    ibz_printf("\n");
}

void
ibz_vec_2_print(const ibz_vec_2_t *vec)
{
    ibz_printf("vector: ");
    for (int i = 0; i < 2; i++) {
        ibz_printf("%Zd ", &((*vec)[i]));
    }
    ibz_printf("\n\n");
}

void
ibz_vec_4_print(const ibz_vec_4_t *vec)
{
    ibz_printf("vector: ");
    for (int i = 0; i < 4; i++) {
        ibz_printf("%Zd ", &((*vec)[i]));
    }
    ibz_printf("\n\n");
}
void
ibz_vec_5_print(const ibz_vec_5_t *vec)
{
    ibz_printf("vector: ");
    for (int i = 0; i < 5; i++) {
        ibz_printf("%Zd ", &((*vec)[i]));
    }
    ibz_printf("\n\n");
}

void
quat_lattice_print(const quat_lattice_t *lat)
{
    ibz_printf("lattice\n");
    ibz_printf("denominator: %Zd\n", (lat->denom));
    ibz_printf("basis: ");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_printf("%Zd ", &((lat->basis)[i][j]));
        }
        ibz_printf("\n       ");
    }
    ibz_printf("\n");
}

void
quat_alg_print(const quat_alg_t *alg)
{
    ibz_printf("quaternion algebra ramified at %Zd and infinity\n\n", &(alg->p));
}

void
quat_alg_elem_print(const quat_alg_elem_t *elem)
{
    ibz_printf("denominator: %Zd\n", (elem->denom));
    ibz_printf("coordinates: ");
    for (int i = 0; i < 4; i++) {
        ibz_printf("%Zd ", &((elem->coord)[i]));
    }
    ibz_printf("\n\n");
}

void
quat_alg_coord_print(const quat_alg_coord_t *coord)
{
    ibz_printf("coordinates: ");
    for (int i = 0; i < 4; i++) {
        ibz_printf("%Zd ", &((*coord)[i]));
    }
    ibz_printf("\n\n");
}

void
quat_order_print(const quat_order_t *order)
{
    ibz_printf("order\n");
    ibz_printf("denominator: %Zd\n", &(order->denom));
    ibz_printf("basis: ");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_printf("%Zd ", &((order->basis)[i][j]));
        }
        ibz_printf("\n       ");
    }
    ibz_printf("\n");
}

void
quat_left_ideal_print(const quat_left_ideal_t *lideal)
{
    ibz_printf("left ideal\n");
    ibz_printf("norm : %Zd\n", &(lideal->norm));
    ibz_printf("denominator: %Zd\n", &(lideal->lattice.denom));
    ibz_printf("basis: ");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_printf("%Zd ", &((lideal->lattice.basis)[i][j]));
        }
        if (i != 3) {
            ibz_printf("\n       ");
        } else {
            ibz_printf("\n");
        }
    }
    if ((lideal->parent_order) != NULL) {
        ibz_printf("parent order denominator: %Zd\n", &(lideal->parent_order->denom));
        ibz_printf("parent order basis: ");
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ibz_printf("%Zd ", &((lideal->parent_order->basis)[i][j]));
            }
            ibz_printf("\n                    ");
        }
    } else {
        ibz_printf("Parent order not given!\n");
    }
    ibz_printf("\n");
}
