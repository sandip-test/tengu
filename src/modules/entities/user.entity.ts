import { Enum } from '@/lib/types';
import { InferSelectModel } from 'drizzle-orm';
import {
  pgTable,
  uuid,
  varchar,
  text,
  timestamp,
  boolean,
  date,
  uniqueIndex,
  index,
  pgEnum,
} from 'drizzle-orm/pg-core';
export enum UserRoleEnum {
  ADMIN = 'ADMIN',
  TEACHER = 'TEACHER',
  STUDENT = 'STUDENT',
}
export enum UserGenderEnum {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
  OTHER = 'OTHER',
}

export const userRoleEnum = pgEnum(
  'user_role',
  Object.values(UserRoleEnum) as Enum<UserRoleEnum>,
);

export const genderEnum = pgEnum(
  'gender',
  Object.values(UserGenderEnum) as Enum<UserGenderEnum>,
);

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 255 }).unique().notNull(),
    password: varchar('password', { length: 255 }).notNull(),
    role: userRoleEnum('role').default(UserRoleEnum.STUDENT),
    firstName: varchar('first_name', { length: 100 }).notNull(),
    lastName: varchar('last_name', { length: 100 }).notNull(),
    phoneNumber: varchar('phone_number', { length: 20 }),
    dateOfBirth: date('date_of_birth'),
    gender: genderEnum('gender'),
    address: text('address'),
    profilePicture: varchar('profile_picture', { length: 500 }),
    isActive: boolean('is_active').default(true),
    lastLogin: timestamp('last_login'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
  (table) => [
    uniqueIndex('users_email_idx').on(table.email),
    index('users_role_idx').on(table.role),
    index('users_is_active_idx').on(table.isActive),
  ],
);
export type USERS = InferSelectModel<typeof users>;
