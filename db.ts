import mongoose from "mongoose";
mongoose.connect(process.env.MONGO_URL!);

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: (["teacher", "student"]), required: true }
});

const classSchema = new mongoose.Schema({
    className: { type: String, required: true },
    teacherId: { type: mongoose.Types.ObjectId, required: true, ref: 'users' },
    studentIds: { type: [mongoose.Types.ObjectId], required: true, ref: 'users' }
});

const attendanceSchema = new mongoose.Schema({
    classId: { type: mongoose.Types.ObjectId, required: true, ref: 'classes' },
    studentId: { type: mongoose.Types.ObjectId, required: true, ref: 'users' },
    status: { type: String, enum: ['present', 'absent'], required: true },
})

export const userModel = mongoose.model('users', userSchema);
export const classModel = mongoose.model('classes', classSchema);
export const attendanceModel = mongoose.model('attendances', attendanceSchema);