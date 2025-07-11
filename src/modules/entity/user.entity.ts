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
// import { genderEnum, userRoleEnum } from './enums';
export const userRoleEnum = pgEnum('user_role', [
  'admin',
  'teacher',
  'student',
]);
export const genderEnum = pgEnum('gender', ['male', 'female', 'other']);

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 255 }).unique().notNull(),
    password: varchar('password', { length: 255 }).notNull(),
    role: userRoleEnum('role').notNull(),
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
