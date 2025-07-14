import { Transform, Type } from 'class-transformer';
import {
  IsBoolean,
  IsNumber,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min,
} from 'class-validator';

export class EnvironmentVariables {
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(65535)
  @Transform(({ value }): number => {
    if (value === undefined || value === '') {
      return 3800;
    }
    return value;
  })
  PORT: number;

  @IsString()
  // starts with postgresql:// for postgres db
  @Matches(/^postgresql:\/\/.*$/)
  DATABASE_URL: string;

  // swagger related
  @IsBoolean()
  @IsOptional()
  @Transform(({ value }) => value === 'true' || value === true)
  ENABLE_SWAGGER: string | boolean;

  @IsString()
  @IsOptional()
  LOG_LEVEL: string;

  @IsString()
  JWT_SECRET: string;
}

export type EnvConfig = InstanceType<typeof EnvironmentVariables>;
