import { ApiProperty, PartialType } from '@nestjs/swagger';
import {
  IsEmail,
  IsString,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsDateString,
  MinLength,
  MaxLength,
} from 'class-validator';
import {
  UserRoleEnum,
  UserGenderEnum,
  USERS,
} from '../../entities/user.entity';

export class CreateUserDto {
  @ApiProperty({
    example: 'john.doe@example.com',
    description: 'User email address',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'password123',
    description: 'User password',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({
    enum: UserRoleEnum,
    example: UserRoleEnum.STUDENT,
    description: 'User role',
  })
  @IsEnum(UserRoleEnum)
  @IsOptional()
  role: UserRoleEnum;

  @ApiProperty({
    example: 'John',
    description: 'First name',
    maxLength: 100,
  })
  @IsString()
  @MaxLength(100)
  firstName: string;

  @ApiProperty({
    example: 'Doe',
    description: 'Last name',
    maxLength: 100,
  })
  @IsString()
  @MaxLength(100)
  lastName: string;

  @ApiProperty({
    example: '+1234567890',
    description: 'Phone number',
    required: false,
    maxLength: 20,
  })
  @IsOptional()
  @IsString()
  @MaxLength(20)
  phoneNumber?: string;

  @ApiProperty({
    example: '1990-01-01',
    description: 'Date of birth',
    required: false,
  })
  @IsOptional()
  @IsDateString()
  dateOfBirth?: string;

  @ApiProperty({
    enum: UserGenderEnum,
    example: UserGenderEnum.MALE,
    description: 'Gender',
    required: false,
  })
  @IsOptional()
  @IsEnum(UserGenderEnum)
  gender?: UserGenderEnum;

  @ApiProperty({
    example: '123 Main St, City, Country',
    description: 'Address',
    required: false,
  })
  @IsOptional()
  @IsString()
  address?: string;

  @ApiProperty({
    example: 'https://example.com/profile.jpg',
    description: 'Profile picture URL',
    required: false,
    maxLength: 500,
  })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  profilePicture?: string;

  @ApiProperty({
    example: true,
    description: 'Whether user is active',
    required: false,
    default: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @ApiProperty({
    example: 'newpassword123',
    description: 'User password',
    minLength: 6,
    required: false,
  })
  @IsOptional()
  @IsString()
  @MinLength(6)
  password?: string;
}

export class UserResponseDto {
  @ApiProperty({
    example: 'uuid-string',
    description: 'User ID',
  })
  id: string;

  @ApiProperty({
    example: 'john.doe@example.com',
    description: 'User email address',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    enum: UserRoleEnum,
    example: UserRoleEnum.STUDENT,
    description: 'User role',
  })
  role: UserRoleEnum;

  @ApiProperty({
    example: 'John',
    description: 'First name',
  })
  firstName: string;

  @ApiProperty({
    example: 'Doe',
    description: 'Last name',
  })
  lastName: string;

  @ApiProperty({
    example: '+1234567890',
    description: 'Phone number',
    required: false,
  })
  phoneNumber?: string;

  @ApiProperty({
    example: '1990-01-01',
    description: 'Date of birth',
    required: false,
  })
  dateOfBirth?: string;

  @ApiProperty({
    enum: UserGenderEnum,
    example: UserGenderEnum.MALE,
    description: 'Gender',
    required: false,
  })
  gender?: UserGenderEnum;

  @ApiProperty({
    example: '123 Main St, City, Country',
    description: 'Address',
    required: false,
  })
  address?: string;

  @ApiProperty({
    example: 'https://example.com/profile.jpg',
    description: 'Profile picture URL',
    required: false,
  })
  profilePicture?: string;

  @ApiProperty({
    example: true,
    description: 'Whether user is active',
  })
  isActive: boolean;

  @ApiProperty({
    example: '2023-01-01T00:00:00.000Z',
    description: 'Last login timestamp',
    required: false,
  })
  lastLogin?: Date;

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
export class UserDto implements Omit<USERS, 'password'> {
  @ApiProperty({
    example: 'uuid-string',
    description: 'User ID',
  })
  id: string;

  @ApiProperty({
    example: 'john.doe@example.com',
    description: 'User email address',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    enum: UserRoleEnum,
    example: UserRoleEnum.STUDENT,
    description: 'User role',
  })
  role: UserRoleEnum;

  @ApiProperty({
    example: 'John',
    description: 'First name',
  })
  firstName: string;

  @ApiProperty({
    example: 'Doe',
    description: 'Last name',
  })
  lastName: string;

  @ApiProperty({
    example: '+1234567890',
    description: 'Phone number',
    nullable: true,
  })
  phoneNumber: string | null;

  @ApiProperty({
    example: '1990-01-01',
    description: 'Date of birth',
    nullable: true,
  })
  dateOfBirth: string | null;

  @ApiProperty({
    enum: UserGenderEnum,
    example: UserGenderEnum.MALE,
    description: 'Gender',
    nullable: true,
  })
  gender: UserGenderEnum | null;

  @ApiProperty({
    example: '123 Main St, City, Country',
    description: 'Address',
    nullable: true,
  })
  address: string | null;

  @ApiProperty({
    example: 'https://example.com/profile.jpg',
    description: 'Profile picture URL',
    nullable: true,
  })
  profilePicture: string | null;

  @ApiProperty({
    example: true,
    description: 'Whether user is active',
  })
  isActive: boolean | null;

  @ApiProperty({
    example: '2023-01-01T00:00:00.000Z',
    description: 'Last login timestamp',
    nullable: true,
  })
  lastLogin: Date | null;

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
export class LoginUserDto {
  @ApiProperty({
    example: 'login@sayaptari.com',
    description: 'Email address for login',
  })
  @IsEmail()
  email: string;
  @ApiProperty({
    example: 'password123',
    description: 'Password for login',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  password: string;
}
