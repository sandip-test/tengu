import { applyDecorators, Type } from '@nestjs/common';
import { ApiProperty, ApiResponse } from '@nestjs/swagger';
import { ApiResponseBaseDto } from './api-response-success.decorator';

/**
 * Custom decorator that creates standardized API Error responses
 * Automatically sets status codes and messages based on HTTP method
 * Wraps the provided schema in a 'data' property to match ResponseInterceptor format
 */
type ApiResponseErrorOptions = {
  description?: string;
  statusCode: number;
  // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
  type: Type<unknown> | Function | [Function] | undefined;
  message?: string;

  /** Indicates, if the response is an array of items */
  isArray?: boolean;
};

let errorResponseCounter = 0;

export function ApiResponseError(options: ApiResponseErrorOptions) {
  const {
    description,
    statusCode,
    type,
    message = '',
    isArray = false,
  } = options;

  if (!type) {
    return applyDecorators(
      ApiResponse({
        status: statusCode,
        description: description,
        type: ApiResponseBaseDto,
      }),
    );
  }

  const uniqueId = ++errorResponseCounter;
  const typeName = (typeof type === 'function' && type.name) || 'Unknown';

  class ErrorResponseTypeDto extends ApiResponseBaseDto {
    @ApiProperty({
      type: type,
      description: message,
      isArray,
    })
    data: ApiResponseErrorOptions['type'] | undefined;
  }

  /** Make the class name unique to avoid Swagger conflicts */
  Object.defineProperty(ErrorResponseTypeDto, 'name', {
    value: `ErrorResponseTypeDto_${typeName}_${uniqueId}`,
  });

  return applyDecorators(
    ApiResponse({
      status: statusCode,
      description: description,
      type: ErrorResponseTypeDto,
    }),
  );
}
type ApiTypedResponseOptions = Omit<ApiResponseErrorOptions, 'method'>;

/**
 * Convenience decorators for specific HTTP methods
 */

export const ApiNotFoundError = (
  options: Partial<ApiTypedResponseOptions> = {},
) => ApiResponseError({ ...options, statusCode: 404, type: undefined });

export const ApiUnauthorizedError = (
  options: Partial<ApiTypedResponseOptions> = {},
) => ApiResponseError({ ...options, statusCode: 401, type: undefined });
