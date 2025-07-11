import { InferSelectModel } from 'drizzle-orm';
import {
  pgTable,
  uuid,
  varchar,
  timestamp,
  boolean,
  date,
  uniqueIndex,
  index,
} from 'drizzle-orm/pg-core';

export const academicYears = pgTable(
  'academic_years',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 100 }).notNull(), // e.g., "2024-2025"
    startDate: date('start_date').notNull(),
    endDate: date('end_date').notNull(),
    isActive: boolean('is_active').default(false),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
  (table) => [
    uniqueIndex('academic_years_name_idx').on(table.name),
    index('academic_years_is_active_idx').on(table.isActive),
  ],
);

export type ACADEMIC_YEARS = InferSelectModel<typeof academicYears>;
