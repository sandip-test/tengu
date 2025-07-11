import {
  pgTable,
  uuid,
  varchar,
  timestamp,
  boolean,
  date,
  decimal,
  index,
  integer,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { users } from './user.entity';
import { InferSelectModel } from 'drizzle-orm';
export const teachers = pgTable(
  'teachers',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .references(() => users.id, { onDelete: 'cascade' })
      .unique()
      .notNull(),
    employeeId: varchar('employee_id', { length: 50 }).unique().notNull(),
    qualification: varchar('qualification', { length: 200 }),
    experience: integer('experience'), // years of experience
    joiningDate: date('joining_date'),
    salary: decimal('salary', { precision: 10, scale: 2 }),

    department: varchar('department', { length: 100 }),
    isActive: boolean('is_active').default(true),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
  (table) => [
    uniqueIndex('teachers_employee_id_idx').on(table.employeeId),
    index('teachers_is_active_idx').on(table.isActive),
  ],
);
export type TEACHERS = InferSelectModel<typeof teachers>;
