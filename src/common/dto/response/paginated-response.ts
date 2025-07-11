/**
 * Generic paginated response DTO
 * Provides consistent pagination structure across all endpoints
 */
class PaginatedResponseDto<T> {
  items: T[];
  meta: {
    totalItems: number;
    totalPages: number;
    currentPage: number;
    itemsPerPage: number;
    hasNext: boolean;
    hasPrev: boolean;
  };

  constructor(response: {
    items: T[];
    meta: {
      totalItems: number;
      totalPages: number;
      currentPage: number;
      itemsPerPage: number;
    };
  }) {
    this.items = response.items;
    this.meta = {
      totalItems: response.meta.totalItems,
      totalPages: response.meta.totalPages,
      currentPage: response.meta.currentPage,
      itemsPerPage: response.meta.itemsPerPage,
      hasNext: response.meta.currentPage < response.meta.totalPages,
      hasPrev: response.meta.currentPage > 1,
    };
  }
}

export { PaginatedResponseDto };
