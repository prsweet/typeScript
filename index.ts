import type { Serve, ServerWebSocket } from "bun";
import { attendanceModel, classModel, userModel } from "./db";
import { addclassSchema, addStudentSchema, loginSchema, signupSchema, startAttendance } from "./types"
import jwt, { type JwtPayload } from "jsonwebtoken";
import mongoose from "mongoose";
const PORT = 3000;

const responses = {
    teacherOnlyWS: {
        "event": "ERROR",
        "data": {
            "message": "Forbidden, teacher event only"
        }
    },
    teacherOnly: {
        "success": false,
        "error": "Forbidden, teacher access required"
    },
    classOwner: {
        "success": false,
        "error": "Forbidden, not class teacher"
    },
    zodError: {
        "success": false,
        "error": "Invalid request schema",
    },
    studentOnlyWS: {
        "event": "ERROR",
        "data": {
            "message": "Forbidden, student event only"
        }
    },
    noActiveSessionWS: {
        "event": "ERROR",
        "data": {
            "message": "No active attendance session"
        }
    }
}

function notfound(name: string) {
    return {
        success: false,
        error: name + " not found"
    };
};

interface userInfo extends JwtPayload {
    userId?: string,
    role?: string
}

type wsData = {
    token: string
}

interface userWs extends ServerWebSocket<wsData> {
    user: {
        userId: string,
        role: string
    }
}

const auth = (handler: (req: userInfo) => Response | Promise<Response>) => {
    return async (req: userInfo) => {
        try {
            const token = req.headers.get("Authorization") as string;
            const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
            req.userId = decoded.userId;
            req.role = decoded.role;
            return handler(req);
        } catch (error) {
            return Response.json({
                "success": false,
                "error": "Unauthorized, token missing or invalid"
            }, 401);
        }
    }
}

function broadcast(message: object) {
    wsUsers.forEach((ws) => {
            ws.send(JSON.stringify(message));
    });
}


let activeSession: { classId: string, teacherId: string, startedAt: string, attendance: Record<string, 'present' | 'absent'> } | null = null;

// function getActiveSession(teacherId: null | string = null): typeof activeSession {
//     let allClear = !activeSession || (teacherId && activeSession.teacherId !== teacherId);
//     return allClear ? activeSession : null;
// } -> tried it still not working;

let wsUsers: userWs[] = [];

Bun.serve({
    port: PORT,
    routes: {
        "/auth/signup": {
            POST: async (req) => {
                const validated = signupSchema.safeParse(await req.json());
                if (!validated.success) return Response.json(responses.zodError, 400);
                const userExist = await userModel.findOne({ email: validated.data.email });
                if (userExist) return Response.json({
                    "success": false,
                    "error": "Email already exists"
                }, 400);
                const user = await userModel.create(validated.data);
                return Response.json({
                    success: true,
                    data: {
                        _id: user._id,
                        name: user.name,
                        email: user.email,
                        role: user.role
                    }
                }, 201);
            }
        },
        "/auth/login": {
            POST: async (req) => {
                const validated = loginSchema.safeParse(await req.json());
                if (!validated.success) return Response.json(responses.zodError, 400);
                const user = await userModel.findOne({ email: validated.data.email, password: validated.data.password });
                if (!user) return Response.json({
                    "success": false,
                    "error": "Invalid email or password"
                }, 400);
                const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET!);
                return Response.json({
                    "success": true,
                    "data": {
                        "token": token
                    }
                })
            }
        },
        "/auth/me": {
            GET: auth(async (req) => {
                const user = await userModel.findOne({ _id: req.userId }).select('-password');
                if (!user) return Response.json(notfound("User"), 404);
                return Response.json({
                    success: true,
                    data: user
                });
            })
        },
        "/class": {
            POST: auth(async (req) => {
                if (req.role !== 'teacher') return Response.json(responses.teacherOnly, 403);
                const validated = addclassSchema.safeParse(await req.json());
                if (!validated.success) return Response.json(responses.zodError, 400);
                const createdClass = await classModel.create({ teacherId: req.userId, className: validated.data.className });
                return Response.json({
                    success: true,
                    data: createdClass
                }, 201);
            })
        },
        "/class/:id/add-student": {
            POST: auth(async (req) => {
                const id = (req as any).params.id;
                if (req.role != 'teacher') return Response.json(responses.teacherOnly, 403);
                const validated = addStudentSchema.safeParse(await req.json());
                if (!validated.success) return Response.json(responses.zodError, 400);
                const studentExist = await userModel.findOne({ _id: validated.data.studentId });
                if (!studentExist) return Response.json(notfound("Student"), 404);
                const updatingClass = await classModel.findOne({ _id: id });
                if (!updatingClass) return Response.json(notfound('Class'), 404);
                if (updatingClass.teacherId.toString() != req.userId) return Response.json(responses.classOwner, 403);
                const studnetAdded = updatingClass.studentIds.some(a => a.toString() == validated.data.studentId);
                if (studnetAdded) return Response.json({
                    success: true,
                    data: updatingClass
                });
                updatingClass.studentIds.push(new mongoose.Types.ObjectId(validated.data.studentId));
                await updatingClass.save();
                return Response.json({
                    success: true,
                    data: updatingClass
                });
            })
        },
        "/class/:id": {
            GET: auth(async (req) => {
                const id = (req as any).params.id;
                const getClass = await classModel.findOne({ _id: id });
                if (!getClass) return Response.json(notfound("Class"), 404);
                const studentEnrolled = getClass.studentIds.find(a => a.toString() == req.userId);
                if (!studentEnrolled && getClass.teacherId.toString() != req.userId) return Response.json(responses.classOwner, 403);
                const studentArray = await userModel.find({ _id: { $in: getClass.studentIds } });
                return Response.json({
                    success: true,
                    data: {
                        _id: getClass._id,
                        className: getClass.className,
                        teacherId: getClass.teacherId,
                        students: studentArray
                    }
                });
            })
        },
        "/students": {
            GET: auth(async (req) => {
                if (req.role !== 'teacher') return Response.json(responses.teacherOnly, 403);
                const students = await userModel.find({ role: 'student' });
                return Response.json({
                    success: true,
                    data: students
                });
            })
        },
        "/class/:id/my-attendance": {
            GET: auth(async (req) => {
                const id = (req as any).params.id;
                const getClass = await classModel.findOne({ _id: id });
                if (!getClass) return Response.json(notfound("Class"), 404);
                const studentEnrolled = getClass.studentIds.some(a => a.toString() == req.userId);
                if (!studentEnrolled) return Response.json({
                    success: false,
                    error: "Student not enrolled in class"
                }, 400);
                const attendancePersisted = await attendanceModel.findOne({ classId: id, studentId: req.userId });
                return Response.json({
                    success: true,
                    data: {
                        classId: id,
                        status: attendancePersisted?.status
                    }
                })
            })
        },
        "/attendance/start": {
            POST: auth(async (req) => {
                if (req.role !== 'teacher') return Response.json(responses.teacherOnly, 403);
                const validated = startAttendance.safeParse(await req.json());
                if (!validated.success) return Response.json(responses.zodError, 400);
                const classExist = await classModel.findOne({ _id: validated.data.classId });
                if (!classExist) return Response.json(notfound("Class"), 404);
                if (classExist.teacherId.toString() != req.userId) return Response.json(responses.classOwner, 403);
                activeSession = {
                    classId: validated.data.classId,
                    startedAt: new Date().toISOString(),
                    attendance: {}
                };
                return Response.json({
                    success: true,
                    data: {
                        classId: activeSession.classId,
                        startedAt: activeSession.startedAt
                    }
                });
            })
        },
        "/ws": {
            GET: async (req, server) => {
                const token = (new URL(req.url)).searchParams.get('token') as string;
                const success = server.upgrade(req, { data: { token: token } });
                if (success) return;
                return Response.json({
                    success: false,
                    error: "Upgrade failed"
                })
            }
        }
    },
    websocket: {
        open: (ws: userWs) => {
            try {
                const decoded = jwt.verify(ws.data.token, process.env.JWT_SECRET!) as JwtPayload;
                ws.user = { userId: decoded.userId, role: decoded.role };
                wsUsers.push(ws);
            } catch (error) {
                ws.send(JSON.stringify({
                    "event": "ERROR",
                    "data": {
                        "message": "Unauthorized or invalid token"
                    }
                }));
                ws.close();
            }
        },
        message: async (ws: userWs, data) => {
            const parsedData = JSON.parse(data.toString());
            let gotEvent: string | null =  parsedData.event;
            let gotData: any | null = parsedData.data;
            if (gotEvent == "ATTENDANCE_MARKED" && !gotData) {
                ws.send(JSON.stringify({
                    event: "ERROR",
                    data: { message: "Invalid message format" }
                }));
                wsUsers = wsUsers.filter((thisWS) => thisWS.user.userId != ws.user.userId);
                ws.close();
                return;
            }
            switch (gotEvent) {
                case "ATTENDANCE_MARKED":
                    if (ws.user.role != 'teacher') {
                        ws.send(JSON.stringify(responses.teacherOnlyWS));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        ws.close();
                        return;
                    }
                    if (!activeSession) {
                        ws.send(JSON.stringify(responses.noActiveSessionWS));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        return;
                    }
                    activeSession.attendance[gotData.studentId] = gotData.status;
                    broadcast({
                        event: "ATTENDANCE_MARKED",
                        data: {
                            studentId: gotData.studentId,
                            status: activeSession.attendance[gotData.studentId]
                        }
                    });
                    break;
                case "TODAY_SUMMARY":
                    if (ws.user.role != 'teacher') {
                        ws.send(JSON.stringify(responses.teacherOnlyWS));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        ws.close();
                        return;
                    }
                    if (!activeSession) {
                        ws.send(JSON.stringify(responses.noActiveSessionWS));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        return;
                    }
                    let present = Object.values(activeSession.attendance).filter(a => a == 'present').length;
                    let absent = Object.values(activeSession.attendance).filter(a => a == 'absent').length;
                    broadcast({
                        event: "TODAY_SUMMARY",
                        data: {
                            present: present,
                            absent: absent,
                            total: absent + present
                        }
                    });
                    break;
                case "MY_ATTENDANCE":
                    if (ws.user.role != 'student') {
                        ws.send(JSON.stringify(responses.studentOnlyWS));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        ws.close();
                        return;
                    }
                    if (!activeSession) {
                        ws.send(JSON.stringify(responses.noActiveSessionWS));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        return;
                    }
                    const studentStatus = activeSession.attendance[ws.user.userId];
                    ws.send(JSON.stringify({
                        event: "MY_ATTENDANCE",
                        data: {
                            status: studentStatus ? studentStatus : "not yet updated"
                        }
                    }));
                    break;
                case "DONE":
                    if (ws.user.role != 'teacher') {
                        ws.send(JSON.stringify(responses.teacherOnlyWS));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        ws.close();
                        return;
                    }
                    if (!activeSession) {
                        ws.send(JSON.stringify(responses.noActiveSessionWS));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        return;
                    }
                    const curClass = await classModel.findOne({ _id: activeSession.classId });
                    if (!curClass) {
                        ws.send(JSON.stringify({
                            event: "ERROR",
                            data: {
                                message: "Class not found"
                            }
                        }));
                        wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
                        ws.close();
                        return;
                    }
                    let present1 = 0;
                    let absent1 = 0;
                    const allStudents = await userModel.find({ _id: { $in: curClass.studentIds } });
                    for (let u of allStudents) {
                        if (!activeSession.attendance[(u._id.toString())]) {
                            activeSession.attendance[(u._id.toString())] = 'absent';
                            absent1++;
                        } else present1++;
                        await attendanceModel.create({ classId: activeSession.classId, studentId: u._id, status: activeSession.attendance[(u._id.toString())] })
                    }
                    broadcast({
                        event: "DONE",
                        data: {
                            message: "Attendance persisted",
                            present: present1,
                            absent: absent1,
                            total: absent1 + present1
                        }
                    });
                    activeSession = null;
                    break;
                default:
                    ws.send(JSON.stringify({
                        event: "ERROR",
                        data: { message: "Unknown event" }
                    }));
                    wsUsers = wsUsers.filter((thisWs) => thisWs.user.userId !== ws.user.userId);
                    ws.close();
                    break;
            }
        },
        close(ws: userWs) {
            if (ws.user) {
                wsUsers = wsUsers.filter((user) => user.user.userId !== ws.user.userId);
            }
        }
    },
})

console.log("Server running on port " + PORT);
