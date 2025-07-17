import { ApiProperty, PartialType } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsBoolean,
  IsDateString,
  MaxLength,
  MinLength,
  Matches,
} from 'class-validator';
import { ACADEMIC_YEARS } from '../../entities/academic-year.entity';

export class CreateAcademicYearDto {
  @ApiProperty({
    example: '2024-2025',
    description: 'Academic year name (format: YYYY-YYYY)',
    maxLength: 100,
  })
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  @Matches(/^\d{4}-\d{4}$/, {
    message: 'Academic year name must be in format YYYY-YYYY (e.g., 2024-2025)',
  })
  name: string;

  @ApiProperty({
    example: '2024-09-01',
    description: 'Academic year start date (YYYY-MM-DD)',
  })
  @IsDateString()
  startDate: string;

  @ApiProperty({
    example: '2025-06-30',
    description: 'Academic year end date (YYYY-MM-DD)',
  })
  @IsDateString()
  endDate: string;

  @ApiProperty({
    example: true,
    description: 'Whether this academic year is currently active',
    required: false,
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

export class UpdateAcademicYearDto extends PartialType(CreateAcademicYearDto) {
  @ApiProperty({
    example: '2024-2026',
    description: 'Updated academic year name',
    required: false,
    maxLength: 100,
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  @Matches(/^\d{4}-\d{4}$/, {
    message: 'Academic year name must be in format YYYY-YYYY (e.g., 2024-2025)',
  })
  name?: string;

  @ApiProperty({
    example: '2024-09-15',
    description: 'Updated start date',
    required: false,
  })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiProperty({
    example: '2025-07-15',
    description: 'Updated end date',
    required: false,
  })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiProperty({
    example: false,
    description: 'Updated active status',
    required: false,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

export class AcademicYearResponseDto {
  @ApiProperty({
    example: 'uuid-string',
    description: 'Academic year ID',
  })
  id: string;

  @ApiProperty({
    example: '2024-2025',
    description: 'Academic year name',
  })
  name: string;

  @ApiProperty({
    example: '2024-09-01',
    description: 'Academic year start date',
  })
  startDate: string;

  @ApiProperty({
    example: '2025-06-30',
    description: 'Academic year end date',
  })
  endDate: string;

  @ApiProperty({
    example: true,
    description: 'Whether this academic year is currently active',
  })
  isActive: boolean;

  @ApiProperty({
    example: '2023-01-01T00:00:00.000Z',
    description: 'Created at timestamp',
  })
  createdAt: Date;

  @ApiProperty({
    example: '2023-01-01T00:00:00.000Z',
    description: 'Updated at timestamp',
  })
  updatedAt: Date;
}

// Main reusable DTO that matches the database entity
export class AcademicYearDto implements ACADEMIC_YEARS {
  @ApiProperty({
    example: 'uuid-string',
    description: 'Academic year ID',
  })
  id: string;

  @ApiProperty({
    example: '2024-2025',
    description: 'Academic year name',
  })
  name: string;

  @ApiProperty({
    example: '2024-09-01',
    description: 'Academic year start date',
  })
  startDate: string;

  @ApiProperty({
    example: '2025-06-30',
    description: 'Academic year end date',
  })
  endDate: string;

  @ApiProperty({
    example: true,
    description: 'Whether this academic year is currently active',
  })
  isActive: boolean | null;

  @ApiProperty({
    example: '2023-01-01T00:00:00.000Z',
    description: 'Created at timestamp',
  })
  createdAt: Date | null;

  @ApiProperty({
    example: '2023-01-01T00:00:00.000Z',
    description: 'Updated at timestamp',
  })
  updatedAt: Date | null;
}

// Extended DTO for responses that include related data
export class AcademicYearWithStatsDto extends AcademicYearDto {
  @ApiProperty({
    description: 'Statistics for this academic year',
    example: {
      totalClasses: 12,
      totalStudents: 350,
      totalTeachers: 25,
    },
  })
  stats?: {
    totalClasses?: number;
    totalStudents?: number;
    totalTeachers?: number;
  };
}

// Query DTO for filtering academic years
export class AcademicYearQueryDto {
  @ApiProperty({
    example: '2024',
    description: 'Search by academic year name',
    required: false,
  })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiProperty({
    example: true,
    description: 'Filter by active status',
    required: false,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiProperty({
    example: '2024-01-01',
    description: 'Filter by start date (from)',
    required: false,
  })
  @IsOptional()
  @IsDateString()
  startDateFrom?: string;

  @ApiProperty({
    example: '2025-12-31',
    description: 'Filter by start date (to)',
    required: false,
  })
  @IsOptional()
  @IsDateString()
  startDateTo?: string;

  @ApiProperty({
    example: '10',
    description: 'Number of items per page',
    required: false,
    default: 10,
  })
  @IsOptional()
  limit?: number;

  @ApiProperty({
    example: '0',
    description: 'Number of items to skip',
    required: false,
    default: 0,
  })
  @IsOptional()
  offset?: number;
}

// DTO for activating/deactivating academic year
export class ToggleActiveAcademicYearDto {
  @ApiProperty({
    example: true,
    description: 'Set active status for the academic year',
  })
  @IsBoolean()
  isActive: boolean;
}
