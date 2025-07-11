import {
  pgTable,
  uuid,
  varchar,
  timestamp,
  uniqueIndex,
  text,
} from 'drizzle-orm/pg-core';
import { academicYears } from './academic-year.entity';
import { InferSelectModel } from 'drizzle-orm';

export const classes = pgTable(
  'classes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 100 }).notNull(), // e.g., "Grade 1", "Grade 2"
    description: text('description'),
    academicYearId: uuid('academic_year_id')
      .references(() => academicYears.id, { onDelete: 'cascade' })
      .notNull(),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
  (table) => [
    uniqueIndex('classes_name_academic_year_idx').on(
      table.name,
      table.academicYearId,
    ),
  ],
);
export type CLASSES = InferSelectModel<typeof classes>;
