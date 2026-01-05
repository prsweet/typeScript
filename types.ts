import { z } from "zod";

export const signupSchema = z.object({
    name: z.string(),
    email: z.email(),
    password: z.string().min(6),
    role: z.enum(["teacher", "student"])
});

export const loginSchema = z.object({
    email: z.email(),
    password: z.string().min(6),
});

export const addclassSchema = z.object({
    className: z.string()
})

export const addStudentSchema = z.object({
    studentId: z.string()
});

export const startAttendance = z.object({
    classId: z.string()
});