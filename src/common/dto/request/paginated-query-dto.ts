import { ApiProperty } from '@nestjs/swagger';
import { Transform, Type } from 'class-transformer';
import { IsIn, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

/**
 * Validation constraints for paginated query parameters
 */
class PaginatedQueryDto {
  @ApiProperty({
    example: 1,
    default: 1,
    required: false,
    description: 'Page number to return',
  })
  @IsOptional()
  @IsInt()
  @Type(() => Number)
  @Min(1)
  page: number = 1;

  @ApiProperty({
    example: 10,
    default: 10,
    required: false,
    description: 'Number of items to return per page',
  })
  @IsOptional()
  @IsInt()
  @Type(() => Number)
  @Min(1)
  @Max(100)
  limit: number = 10;

  @ApiProperty({
    example: 'createdAt',
    required: false,
    description: 'Field to sort by',
  })
  @IsOptional()
  @IsString()
  sortBy?: string;

  @ApiProperty({
    example: 'desc',
    default: 'desc',
    enum: ['asc', 'desc'],
    required: false,
    description: 'Sort order',
  })
  @Transform(({ value }) => (value ? value.toLowerCase() : 'desc'))
  @IsOptional()
  @IsIn(['asc', 'desc'])
  sortOrder: string = 'desc';

  @ApiProperty({
    example: 'John Doe',
    default: '',
    required: false,
    description: 'Search query ',
  })
  @Transform(({ value }) => (value ? value.trim() : ''))
  @IsOptional()
  @IsString()
  query: string = '';
}

export { PaginatedQueryDto };
