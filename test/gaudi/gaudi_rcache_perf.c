/**
 * Copyright (c) 2025, Habana Labs Ltd. an Intel Company. All rights reserved.
 * See file LICENSE for terms.
 */

#include <uct/api/uct.h>
#include <ucs/time/time.h>
#include <ucs/sys/sys.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ucs_status_t find_gaudi_component(uct_component_h *component_p)
{
    uct_component_h *components;
    unsigned num_components;
    ucs_status_t status;

    status = uct_query_components(&components, &num_components);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to query components\n");
        return status;
    }

    printf("Found %u total components:\n", num_components);
    for (unsigned i = 0; i < num_components; ++i) {
        uct_component_attr_t attr;
        attr.field_mask = UCT_COMPONENT_ATTR_FIELD_NAME;
        status = uct_component_query(components[i], &attr);
        if (status == UCS_OK) {
            printf("  Component %u: %s\n", i, attr.name);
            if (!strcmp(attr.name, "gaudi_copy")) {
                *component_p = components[i];
                uct_release_component_list(components);
                return UCS_OK;
            }
        } else {
            printf("  Component %u: <query failed with status %d>\n", i, status);
        }
    }

    fprintf(stderr, "Gaudi component not found\n");
    uct_release_component_list(components);
    return UCS_ERR_NO_DEVICE;
}

int main(int argc, char **argv) {
    uct_component_h gaudi_component;
    uct_md_h md;
    uct_md_config_t *md_config;
    ucs_status_t status;

    status = find_gaudi_component(&gaudi_component);
    if (status != UCS_OK) {
        return -1;
    }

    status = uct_md_config_read(gaudi_component, NULL, NULL, &md_config);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to read MD config\n");
        return -1;
    }

    status = uct_md_open(gaudi_component, "gaudi_copy:0", md_config, &md);
    uct_config_release(md_config);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to open MD\n");
        return -1;
    }

    size_t length = 1024 * 1024; // 1 MB
    void *buffer = malloc(length);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate test buffer\n");
        status = UCS_ERR_NO_MEMORY;
        goto out_close_md;
    }

    int num_iterations = 1000;
    uct_mem_h memh;
    ucs_time_t start_time, end_time;
    double total_ns = 0;

    unsigned flags = 0;

    // Perform one registration/deregistration cycle to warm up the cache
    // and measure the "miss" time.
    start_time = ucs_get_time();
    status = uct_md_mem_reg(md, buffer, length, flags, &memh);
    end_time = ucs_get_time();
    if (status != UCS_OK) {
        fprintf(stderr, "Initial registration failed\n");
        goto out_free_buffer;
    }
    printf("Initial registration (cache miss) time: %.2f ns\n",
           ucs_time_to_nsec(end_time - start_time));
    uct_md_mem_dereg(md, memh);


    // Now, time the repeated registrations, which should be cache hits.
    for (int i = 0; i < num_iterations; ++i) {
        start_time = ucs_get_time();
        status = uct_md_mem_reg(md, buffer, length, flags, &memh);
        if (status != UCS_OK) {
            fprintf(stderr, "Repeated registration failed\n");
            goto out_free_buffer;
        }

        status = uct_md_mem_dereg(md, memh);
        if (status != UCS_OK) {
            fprintf(stderr, "Repeated deregistration failed\n");
            goto out_free_buffer;
        }
        end_time = ucs_get_time();
        total_ns += ucs_time_to_nsec(end_time - start_time);
    }

    printf("Average registration time over %d iterations (cache hit): %.2f ns\n",
           num_iterations, total_ns / num_iterations);

out_free_buffer:
    free(buffer);
out_close_md:
    uct_md_close(md);
    return (status == UCS_OK) ? 0 : -1;
}