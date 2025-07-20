import { InferSelectModel, relations } from 'drizzle-orm';
import {
  pgTable,
  uuid,
  varchar,
  timestamp,
  boolean,
  date,
  uniqueIndex,
  index,
  text,
} from 'drizzle-orm/pg-core';
import { users } from './user.entity';

// Enhanced Students Table
export const students = pgTable(
  'students',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .references(() => users.id, { onDelete: 'cascade' })
      .unique()
      .notNull(),
    studentId: varchar('student_id', { length: 50 }).unique().notNull(), // Roll number
    admissionDate: date('admission_date').notNull(),
    guardianName: varchar('guardian_name', { length: 100 }),
    guardianPhone: varchar('guardian_phone', { length: 20 }),
    guardianEmail: varchar('guardian_email', { length: 255 }),
    bloodGroup: varchar('blood_group', { length: 5 }),
    emergencyContact: varchar('emergency_contact', { length: 20 }),
    previousSchool: varchar('previous_school', { length: 200 }),
    medicalConditions: text('medical_conditions'), // Added for health tracking
    isActive: boolean('is_active').default(true),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
  (table) => [
    // Indexes for performance
    uniqueIndex('students_student_id_idx').on(table.studentId),
    uniqueIndex('students_user_id_idx').on(table.userId),
    index('students_is_active_idx').on(table.isActive),
    index('students_admission_date_idx').on(table.admissionDate),
    index('students_guardian_email_idx').on(table.guardianEmail),
  ],
);

export const studentsRelations = relations(students, ({ one }) => ({
  user: one(users, {
    fields: [students.userId],
    references: [users.id],
  }),
  // Add these relations when you create enrollment tables
  // enrollments: many(enrollments),
  // attendance: many(attendance),
  // grades: many(grades),
}));

export type STUDENTS = InferSelectModel<typeof students>;
