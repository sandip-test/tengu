# Authentication Flow & Table Structure Design

## Recommended Approach: Hybrid Pattern

Based on your existing schema, I recommend continuing with your current approach but with some enhancements:

### 1. **Main Users Table + Role-Specific Tables**

- Keep the `users` table as the central authentication table
- Create role-specific tables (`teachers`, `students`, `admins`) for role-specific data
- This provides flexibility for bulk operations while maintaining data integrity

### 2. **Why This Approach Works Best:**

#### ✅ **Advantages:**

- **Bulk Operations**: Easy to create students in bulk - create user records first, then student records
- **Role-Specific Data**: Each role can have specific fields without cluttering the main table
- **Authentication Simplicity**: Single login flow using the users table
- **Data Integrity**: Referential integrity between users and role tables
- **Scalability**: Easy to extend with new roles or role-specific features
- **Performance**: Indexed properly for fast lookups

#### ❌ **Alternative Approaches (Why Not):**

- **Single Users Table Only**: Would require many nullable columns for role-specific data
- **Separate Tables Only**: Would complicate authentication and duplicate common fields
- **Table Per Role**: Would make cross-role queries and reporting difficult

## Recommended Schema Structure

```typescript
// Your existing users table (keep as is)
export const users = pgTable('users', {
  // ... your existing fields
});

// Your existing teachers table (keep as is)
export const teachers = pgTable('teachers', {
  // ... your existing fields
});

// Add students table (similar to teachers)
export const students = pgTable('students', {
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
  isActive: boolean('is_active').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Add admins table for completeness
export const admins = pgTable('admins', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .unique()
    .notNull(),
  adminLevel: varchar('admin_level', { length: 20 }).default('SCHOOL'), // SCHOOL, DISTRICT, etc.
  permissions: jsonb('permissions'), // Specific permissions
  isActive: boolean('is_active').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});
```

## Authentication Flow Design

### 1. **Login Process**

```typescript
// Single authentication endpoint
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "password123"
}

// Response includes role information
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "role": "STUDENT",
    "firstName": "John",
    "lastName": "Doe"
  },
  "token": "jwt_token",
  "redirectTo": "/dashboard/student" // Role-based redirect
}
```

### 2. **Role Detection & Redirection**

```typescript
// Middleware checks role and redirects appropriately
if (user.role === 'ADMIN') redirect('/dashboard/admin');
if (user.role === 'TEACHER') redirect('/dashboard/teacher');
if (user.role === 'STUDENT') redirect('/dashboard/student');
```

### 3. **Data Fetching Strategy**

```typescript
// For each role, fetch additional data as needed
const getCompleteUserData = async (userId: string, role: UserRole) => {
  const baseUser = await getUserById(userId);

  switch (role) {
    case 'ADMIN':
      const adminData = await getAdminByUserId(userId);
      return { ...baseUser, adminDetails: adminData };

    case 'TEACHER':
      const teacherData = await getTeacherByUserId(userId);
      return { ...baseUser, teacherDetails: teacherData };

    case 'STUDENT':
      const studentData = await getStudentByUserId(userId);
      return { ...baseUser, studentDetails: studentData };
  }
};
```

## Bulk Student Creation Strategy

### 1. **Admin Interface for Bulk Upload**

```typescript
// CSV/Excel upload endpoint
POST /api/admin/students/bulk-create
Content-Type: multipart/form-data

// Expected CSV format:
// firstName,lastName,email,dateOfBirth,guardianName,guardianPhone,class,section
// John,Doe,john@email.com,2010-05-15,Jane Doe,1234567890,Grade 5,A
```

### 2. **Bulk Creation Process**

```typescript
const bulkCreateStudents = async (studentsData: StudentBulkData[]) => {
  return await db.transaction(async (tx) => {
    const results = [];

    for (const studentData of studentsData) {
      // 1. Create user record
      const user = await tx
        .insert(users)
        .values({
          email: studentData.email,
          password: await hashPassword(generateTemporaryPassword()),
          role: 'STUDENT',
          firstName: studentData.firstName,
          lastName: studentData.lastName,
          dateOfBirth: studentData.dateOfBirth,
          // ... other user fields
        })
        .returning();

      // 2. Create student record
      const student = await tx
        .insert(students)
        .values({
          userId: user[0].id,
          studentId: generateStudentId(),
          admissionDate: new Date(),
          guardianName: studentData.guardianName,
          guardianPhone: studentData.guardianPhone,
          // ... other student fields
        })
        .returning();

      // 3. Enroll in class/section if specified
      if (studentData.classId && studentData.sectionId) {
        await tx.insert(enrollments).values({
          studentId: student[0].id,
          classId: studentData.classId,
          sectionId: studentData.sectionId,
          academicYearId: getCurrentAcademicYearId(),
        });
      }

      results.push({ user: user[0], student: student[0] });
    }

    return results;
  });
};
```

### 3. **Password Management for Bulk Users**

```typescript
// Generate temporary passwords and send via email/SMS
const handleBulkPasswordDistribution = async (createdStudents: any[]) => {
  for (const { user, student } of createdStudents) {
    const tempPassword = generateTemporaryPassword();

    // Send credentials via email to guardian
    await sendWelcomeEmail({
      to: student.guardianEmail || user.email,
      studentName: `${user.firstName} ${user.lastName}`,
      studentId: student.studentId,
      email: user.email,
      tempPassword: tempPassword,
    });

    // Mark user as requiring password change on first login
    await updateUser(user.id, {
      mustChangePassword: true,
      passwordResetToken: generateResetToken(),
    });
  }
};
```

## Database Migration Strategy

### 1. **Add Missing Tables**

```sql
-- Add students table
CREATE TABLE students (
  -- ... fields as defined above
);

-- Add admins table
CREATE TABLE admins (
  -- ... fields as defined above
);

-- Add enrollment table (if not exists)
CREATE TABLE enrollments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id UUID REFERENCES students(id) ON DELETE CASCADE,
  class_id UUID REFERENCES classes(id) ON DELETE CASCADE,
  section_id UUID REFERENCES sections(id) ON DELETE CASCADE,
  academic_year_id UUID REFERENCES academic_years(id) ON DELETE CASCADE,
  enrollment_date DATE NOT NULL,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

### 2. **Create Indexes for Performance**

```sql
-- Students table indexes
CREATE INDEX idx_students_student_id ON students(student_id);
CREATE INDEX idx_students_is_active ON students(is_active);
CREATE INDEX idx_students_admission_date ON students(admission_date);

-- Enrollments indexes
CREATE INDEX idx_enrollments_student_id ON enrollments(student_id);
CREATE INDEX idx_enrollments_class_section ON enrollments(class_id, section_id);
CREATE INDEX idx_enrollments_academic_year ON enrollments(academic_year_id);
```

## Security Considerations

### 1. **Role-Based Access Control**

```typescript
// Middleware to check permissions
const requireRole = (allowedRoles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = req.user.role;
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Usage
app.post(
  '/api/admin/students/bulk-create',
  authenticate,
  requireRole(['ADMIN']),
  bulkCreateStudentsHandler,
);
```

### 2. **Data Validation**

```typescript
// Validate bulk student data
const validateStudentData = (data: any[]) => {
  const errors = [];

  data.forEach((student, index) => {
    if (!student.email || !isValidEmail(student.email)) {
      errors.push(`Row ${index + 1}: Invalid email`);
    }
    if (!student.firstName || !student.lastName) {
      errors.push(`Row ${index + 1}: Name is required`);
    }
    // ... more validations
  });

  return errors;
};
```

## Summary

✅ **Recommended Approach:**

- Keep your current `users` table structure
- Add `students` and `admins` tables (similar to your `teachers` table)
- Use single authentication flow with role-based redirection
- Implement bulk creation using database transactions
- Handle temporary password generation and distribution

This approach gives you the flexibility for bulk operations while maintaining data integrity and a clean authentication flow.

````ts
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
  pgEnum,
  time,
  integer,
} from 'drizzle-orm/pg-core';
import { users } from './user.entity';
import { students } from './student.entity';
import { teachers } from './teacher.entity';
import { classes } from './class.entity';
import { sections } from './section.entity';
import { subjects } from './subject.entity'; // You'll need this for subject-wise attendance

// Attendance Status Enum
export const attendanceStatusEnum = pgEnum('attendance_status', [
  'present',
  'absent',
  'late',
  'excused',
  'half_day',
  'sick',
  'emergency',
]);

// Attendance Type Enum
export const attendanceTypeEnum = pgEnum('attendance_type', [
  'daily', // Full day attendance
  'period', // Subject-wise/period-wise attendance
]);

// Main Attendance Table
export const attendance = pgTable(
  'attendance',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    studentId: uuid('student_id')
      .references(() => students.id, { onDelete: 'cascade' })
      .notNull(),
    classId: uuid('class_id')
      .references(() => classes.id, { onDelete: 'cascade' })
      .notNull(),
    sectionId: uuid('section_id')
      .references(() => sections.id, { onDelete: 'cascade' })
      .notNull(),
    subjectId: uuid('subject_id').references(() => subjects.id, { onDelete: 'set null' }), // Nullable for daily attendance
    attendanceDate: date('attendance_date').notNull(),
    attendanceType: attendanceTypeEnum('attendance_type').default('daily'),
    status: attendanceStatusEnum('status').notNull(),
    timeIn: time('time_in'), // When student arrived (for late tracking)
    timeOut: time('time_out'), // For half-day tracking
    periodNumber: integer('period_number'), // For period-wise attendance
    markedBy: uuid('marked_by')
      .references(() => teachers.id, { onDelete: 'set null' })
      .notNull(), // Teacher who marked attendance
    remarks: text('remarks'), // Additional notes
    isManualEntry: boolean('is_manual_entry').default(false), // Was it marked manually or auto?
    markedAt: timestamp('marked_at').defaultNow(),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
  (table) => [
    // Unique constraint: One attendance record per student per date per subject/period
    uniqueIndex('attendance_student_date_subject_period_idx').on(
      table.studentId,
      table.attendanceDate,
      table.subjectId,
      table.periodNumber
    ),
    // Performance indexes
    index('attendance_student_date_idx').on(table.studentId, table.attendanceDate),
    index('attendance_class_section_date_idx').on(table.classId, table.sectionId, table.attendanceDate),
    index('attendance_date_status_idx').on(table.attendanceDate, table.status),
    index('attendance_marked_by_idx').on(table.markedBy),
    index('attendance_type_idx').on(table.attendanceType),
  ],
);

// Attendance Summary Table (for performance - calculated daily)
export const attendanceSummary = pgTable(
  'attendance_summary',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    studentId: uuid('student_id')
      .references(() => students.id, { onDelete: 'cascade' })
      .notNull(),
    classId: uuid('class_id')
      .references(() => classes.id, { onDelete: 'cascade' })
      .notNull(),
    sectionId: uuid('section_id')
      .references(() => sections.id, { onDelete: 'cascade' })
      .notNull(),
    month: integer('month').notNull(), // 1-12
    year: integer('year').notNull(),
    totalDays: integer('total_days').default(0),
    presentDays: integer('present_days').default(0),
    absentDays: integer('absent_days').default(0),
    lateDays: integer('late_days').default(0),
    excusedDays: integer('excused_days').default(0),
    halfDays: integer('half_days').default(0),
    attendancePercentage: integer('attendance_percentage').default(0), // Stored as integer (95 for 95%)
    lastUpdated: timestamp('last_updated').defaultNow(),
    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => [
    uniqueIndex('attendance_summary_student_month_year_idx').on(
      table.studentId,
      table.month,
      table.year
    ),
    index('attendance_summary_class_section_idx').on(table.classId, table.sectionId),
    index('attendance_summary_percentage_idx').on(table.attendancePercentage),
  ],
);

// Attendance Rules/Settings
export const attendanceSettings = pgTable(
  'attendance_settings',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    classId: uuid('class_id').references(() => classes.id, { onDelete: 'cascade' }),
    sectionId: uuid('section_id').references(() => sections.id, { onDelete: 'cascade' }),
    // Timing settings
    schoolStartTime: time('school_start_time').default('08:00:00'),
    schoolEndTime: time('school_end_time').default('15:00:00'),
    lateThresholdMinutes: integer('late_threshold_minutes').default(15), // Late after 15 minutes
    halfDayThresholdMinutes: integer('half_day_threshold_minutes').default(240), // Half day if less than 4 hours
    // Attendance requirements
    minimumAttendancePercentage: integer('minimum_attendance_percentage').default(75),
    allowManualEntry: boolean('allow_manual_entry').default(true),
    requireRemarks: boolean('require_remarks').default(false),
    // Auto-marking settings
    enableAutoMarking: boolean('enable_auto_marking').default(false),
    autoMarkTime: time('auto_mark_time').default('09:00:00'),
    isActive: boolean('is_active').default(true),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
  (table) => [
    index('attendance_settings_class_section_idx').on(table.classId, table.sectionId),
  ],
);

// Attendance Templates (for bulk marking)
export const attendanceTemplates = pgTable(
  'attendance_templates',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 100 }).notNull(), // e.g., "Regular Day", "Half Day", "Field Trip"
    description: text('description'),
    classId: uuid('class_id').references(() => classes.id, { onDelete: 'cascade' }),
    sectionId: uuid('section_id').references(() => sections.id, { onDelete: 'cascade' }),
    defaultStatus: attendanceStatusEnum('default_status').default('present'),
    templateData: text('template_data'), // JSON string of student attendance data
    createdBy: uuid('created_by').references(() => teachers.id, { onDelete: 'set null' }),
    isActive: boolean('is_active').default(true),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
  },
);

// Relations
export const attendanceRelations = relations(attendance, ({ one }) => ({
  student: one(students, {
    fields: [attendance.studentId],
    references: [students.id],
  }),
  class: one(classes, {
    fields: [attendance.classId],
    references: [classes.id],
  }),
  section: one(sections, {
    fields: [attendance.sectionId],
    references: [sections.id],
  }),
  subject: one(subjects, {
    fields: [attendance.subjectId],
    references: [subjects.id],
  }),
  markedByTeacher: one(teachers, {
    fields: [attendance.markedBy],
    references: [teachers.id],
  }),
}));

export const attendanceSummaryRelations = relations(attendanceSummary, ({ one }) => ({
  student: one(students, {
    fields: [attendanceSummary.studentId],
    references: [students.id],
  }),
  class: one(classes, {
    fields: [attendanceSummary.classId],
    references: [classes.id],
  }),
  section: one(sections, {
    fields: [attendanceSummary.sectionId],
    references: [sections.id],
  }),
}));

export const attendanceSettingsRelations = relations(attendanceSettings, ({ one }) => ({
  class: one(classes, {
    fields: [attendanceSettings.classId],
    references: [classes.id],
  }),
  section: one(sections, {
    fields: [attendanceSettings.sectionId],
    references: [sections.id],
  }),
}));

export const attendanceTemplatesRelations = relations(attendanceTemplates, ({ one }) => ({
  class: one(classes, {
    fields: [attendanceTemplates.classId],
    references: [classes.id],
  }),
  section: one(sections, {
    fields: [attendanceTemplates.sectionId],
    references: [sections.id],
  }),
  createdByTeacher: one(teachers, {
    fields: [attendanceTemplates.createdBy],
    references: [teachers.id],
  }),
}));

// TypeScript Types
export type ATTENDANCE = InferSelectModel<typeof attendance>;
export type ATTENDANCE_SUMMARY = InferSelectModel<typeof attendanceSummary>;
export type ATTENDANCE_SETTINGS = InferSelectModel<typeof attendanceSettings>;
export type ATTENDANCE_TEMPLATES = InferSelectModel<typeof attendanceTemplates>;

export type AttendanceStatus = typeof attendanceStatusEnum.enumValues[number];
export type AttendanceType = typeof attendanceTypeEnum.enumValues[number];

// Helper Types for API
export interface BulkAttendanceData {
  studentId: string;
  status: AttendanceStatus;
  timeIn?: string;
  timeOut?: string;
  remarks?: string;
}

export interface MarkAttendanceRequest {
  classId: string;
  sectionId: string;
  subjectId?: string;
  attendanceDate: string;
  attendanceType: AttendanceType;
  periodNumber?: number;
  attendance: BulkAttendanceData[];
}

export interface AttendanceReport {
  studentId: string;
  studentName: string;
  totalDays: number;
  presentDays: number;
  absentDays: number;
  lateCount: number;
  attendancePercentage: number;
  lastAbsent?: string;
  trend: 'improving' | 'declining' | 'stable';
}

// Utility Functions Types
export interface AttendanceFilters {
  classId?: string;
  sectionId?: string;
  studentId?: string;
  dateFrom?: string;
  dateTo?: string;
  status?: AttendanceStatus[];
  attendanceType?: AttendanceType;
}

export interface AttendanceStats {
  totalStudents: number;
  presentToday: number;
  absentToday: number;
  lateToday: number;
  attendanceRate: number;
  monthlyTrend: Array<{
    date: string;
    presentCount: number;
    totalCount: number;
    percentage: number;
  }>;
}```
````

## 🎯 **Key Features of This Attendance Schema:**

### 1. **Flexible Attendance Types**

- **Daily Attendance**: Full day present/absent
- **Period-wise Attendance**: Subject/class-wise attendance
- **Multiple Status Options**: Present, Absent, Late, Excused, Half-day, Sick, Emergency

### 2. **Performance Optimizations**

- **Summary Table**: Pre-calculated monthly statistics
- **Strategic Indexes**: Fast queries on common patterns
- **Unique Constraints**: Prevent duplicate entries

### 3. **Advanced Features**

- **Time Tracking**: Late arrival and early departure times
- **Bulk Operations**: Templates for quick marking
- **Configurable Rules**: Different settings per class/section
- **Audit Trail**: Who marked attendance and when

### 4. **Real-world Considerations**

- **Manual vs Auto**: Track if attendance was manually entered
- **Remarks Field**: For special circumstances
- **Flexible Timing**: Configurable late/half-day thresholds
- **Template System**: For recurring patterns (field trips, etc.)

## 📊 **Usage Examples:**

### **Daily Attendance Marking**

```typescript
// Mark daily attendance for a class
const markDailyAttendance = async (data: MarkAttendanceRequest) => {
  const attendanceRecords = data.attendance.map((student) => ({
    studentId: student.studentId,
    classId: data.classId,
    sectionId: data.sectionId,
    attendanceDate: data.attendanceDate,
    attendanceType: 'daily',
    status: student.status,
    timeIn: student.timeIn,
    remarks: student.remarks,
    markedBy: teacherId,
  }));

  await db.insert(attendance).values(attendanceRecords);
};
```

### **Attendance Reports**

```typescript
// Get monthly attendance summary
const getAttendanceSummary = async (
  studentId: string,
  month: number,
  year: number,
) => {
  return await db
    .select()
    .from(attendanceSummary)
    .where(
      and(
        eq(attendanceSummary.studentId, studentId),
        eq(attendanceSummary.month, month),
        eq(attendanceSummary.year, year),
      ),
    );
};
```

## 🔄 **Integration with Your Existing Schema:**

This attendance schema perfectly integrates with your current entities:

- ✅ Links to `students` table
- ✅ Links to `classes` and `sections`
- ✅ Links to `teachers` for marking
- ✅ Supports `subjects` for period-wise attendance
- ✅ Follows your naming and structure conventions

## 📈 **Benefits:**

1. **Scalable**: Handles both daily and period-wise attendance
2. **Performant**: Summary tables for fast reporting
3. **Flexible**: Configurable rules per class
4. **Complete**: Covers all attendance scenarios
5. **Auditable**: Full tracking of who marked what when

This schema supports all the attendance requirements you mentioned for Admin, Teacher, and Student roles!
