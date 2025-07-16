import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsUUID,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateClassDto {
  @ApiProperty({
    example: 'Grade 5',
    description: 'Class name',
    maxLength: 100,
  })
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  name: string;

  @ApiProperty({
    example: 'Fifth grade class for students aged 10-11',
    description: 'Class description',
    required: false,
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty({
    example: 'uuid-string',
    description: 'Academic year ID this class belongs to',
  })
  @IsUUID()
  academicYearId: string;
}
