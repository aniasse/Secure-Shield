import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "academy", level: "info" });

// Configuration
const config = {
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  app: {
    port: parseInt(process.env.PORT || "8086"),
  },
};

// Types
interface Course {
  id: string;
  title: string;
  description: string;
  level: "beginner" | "intermediate" | "advanced";
  duration_hours: number;
  modules: Module[];
  instructor: string;
  tags: string[];
  price: number; // XOF
  currency: string;
  thumbnail?: string;
  published: boolean;
  created_at: string;
  updated_at: string;
}

interface Module {
  id: string;
  title: string;
  description: string;
  order: number;
  lessons: Lesson[];
}

interface Lesson {
  id: string;
  title: string;
  type: "video" | "text" | "quiz" | "lab";
  content: string; // URL or markdown
  duration_minutes: number;
  order: number;
}

interface Enrollment {
  id: string;
  user_id: string;
  course_id: string;
  enrolled_at: string;
  progress: number; // 0-100
  completed_lessons: string[];
  last_accessed?: string;
  certificate_issued?: boolean;
  certificate_url?: string;
}

interface Quiz {
  id: string;
  lesson_id: string;
  questions: QuizQuestion[];
  passing_score: number; // percentage
}

interface QuizQuestion {
  id: string;
  question: string;
  type: "multiple_choice" | "true_false" | "fill_blank";
  options?: string[];
  correct_answer: string | string[];
  explanation?: string;
}

interface UserProgress {
  user_id: string;
  course_id: string;
  lesson_id: string;
  completed: boolean;
  time_spent_seconds: number;
  last_accessed: string;
}

// Academy Service
class AcademyService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  // Course Management
  async createCourse(
    course: Omit<Course, "id" | "created_at" | "updated_at">,
  ): Promise<Course> {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const fullCourse: Course = {
      id,
      ...course,
      created_at: now,
      updated_at: now,
    };

    await this.redis.set(`course:${id}`, JSON.stringify(fullCourse));
    await this.redis.sadd("courses:all", id);

    // Index by tags
    for (const tag of course.tags) {
      await this.redis.sadd(`courses:tag:${tag}`, id);
    }

    log.info({ course: course.title }, "Course created");
    return fullCourse;
  }

  async getCourse(id: string): Promise<Course | null> {
    const data = await this.redis.get(`course:${id}`);
    return data ? JSON.parse(data) : null;
  }

  async listCourses(filters?: {
    level?: string;
    tag?: string;
    published?: boolean;
  }): Promise<Course[]> {
    let courseIds: string[];

    if (filters?.tag) {
      courseIds = await this.redis.smembers(`courses:tag:${filters.tag}`);
    } else {
      courseIds = await this.redis.smembers("courses:all");
    }

    const courses: Course[] = [];
    for (const id of courseIds) {
      const course = await this.getCourse(id);
      if (!course) continue;

      if (filters?.level && course.level !== filters.level) continue;
      if (
        filters?.published !== undefined &&
        course.published !== filters.published
      )
        continue;

      courses.push(course);
    }

    return courses.sort(
      (a, b) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    );
  }

  async updateCourse(
    id: string,
    updates: Partial<Course>,
  ): Promise<Course | null> {
    const course = await this.getCourse(id);
    if (!course) return null;

    const updated: Course = {
      ...course,
      ...updates,
      updated_at: new Date().toISOString(),
    };

    await this.redis.set(`course:${id}`, JSON.stringify(updated));
    return updated;
  }

  // Enrollment
  async enrollUser(userId: string, courseId: string): Promise<Enrollment> {
    const course = await this.getCourse(courseId);
    if (!course) throw new Error("Course not found");

    const enrollment: Enrollment = {
      id: crypto.randomUUID(),
      user_id: userId,
      course_id: courseId,
      enrolled_at: new Date().toISOString(),
      progress: 0,
      completed_lessons: [],
    };

    await this.redis.set(
      `enrollment:${enrollment.id}`,
      JSON.stringify(enrollment),
    );
    await this.redis.sadd(`enrollments:user:${userId}`, enrollment.id);
    await this.redis.sadd(`enrollments:course:${courseId}`, enrollment.id);

    log.info({ userId, courseId }, "User enrolled");
    return enrollment;
  }

  async getEnrollment(id: string): Promise<Enrollment | null> {
    const data = await this.redis.get(`enrollment:${id}`);
    return data ? JSON.parse(data) : null;
  }

  async getUserEnrollments(userId: string): Promise<Enrollment[]> {
    const ids = await this.redis.smembers(`enrollments:user:${userId}`);
    const enrollments: Enrollment[] = [];

    for (const id of ids) {
      const enrollment = await this.getEnrollment(id);
      if (enrollment) enrollments.push(enrollment);
    }

    return enrollments;
  }

  async updateProgress(
    enrollmentId: string,
    lessonId: string,
    timeSpent: number,
  ): Promise<Enrollment | null> {
    const enrollment = await this.getEnrollment(enrollmentId);
    if (!enrollment) return null;

    const course = await this.getCourse(enrollment.course_id);
    if (!course) return null;

    // Count total lessons
    const totalLessons = course.modules.reduce(
      (sum, m) => sum + m.lessons.length,
      0,
    );

    // Add to completed lessons if not already
    if (!enrollment.completed_lessons.includes(lessonId)) {
      enrollment.completed_lessons.push(lessonId);
    }

    // Calculate progress
    enrollment.progress = Math.round(
      (enrollment.completed_lessons.length / totalLessons) * 100,
    );
    enrollment.last_accessed = new Date().toISOString();

    await this.redis.set(
      `enrollment:${enrollmentId}`,
      JSON.stringify(enrollment),
    );

    // Issue certificate if completed
    if (enrollment.progress === 100 && !enrollment.certificate_issued) {
      await this.issueCertificate(enrollment);
    }

    return enrollment;
  }

  private async issueCertificate(enrollment: Enrollment): Promise<void> {
    const course = await this.getCourse(enrollment.course_id);
    if (!course) return;

    enrollment.certificate_issued = true;
    enrollment.certificate_url = `https://academy.afri-secure.com/cert/${enrollment.id}`;

    await this.redis.set(
      `enrollment:${enrollment.id}`,
      JSON.stringify(enrollment),
    );

    log.info({ enrollmentId: enrollment.id }, "Certificate issued");
  }

  // Quiz Management
  async createQuiz(quiz: Omit<Quiz, "id">): Promise<Quiz> {
    const id = crypto.randomUUID();
    const fullQuiz: Quiz = { id, ...quiz };

    await this.redis.set(`quiz:${id}`, JSON.stringify(fullQuiz));
    await this.redis.set(`quiz:lesson:${quiz.lesson_id}`, id);

    return fullQuiz;
  }

  async getQuiz(lessonId: string): Promise<Quiz | null> {
    const quizId = await this.redis.get(`quiz:lesson:${lessonId}`);
    if (!quizId) return null;

    const data = await this.redis.get(`quiz:${quizId}`);
    return data ? JSON.parse(data) : null;
  }

  async submitQuiz(
    lessonId: string,
    answers: Record<string, string>,
  ): Promise<{
    passed: boolean;
    score: number;
    correct_answers: Record<string, boolean>;
  }> {
    const quiz = await this.getQuiz(lessonId);
    if (!quiz) throw new Error("Quiz not found");

    let correct = 0;
    const correctAnswers: Record<string, boolean> = {};

    for (const question of quiz.questions) {
      const userAnswer = answers[question.id];
      const isCorrect = Array.isArray(question.correct_answer)
        ? question.correct_answer.includes(userAnswer)
        : question.correct_answer === userAnswer;

      if (isCorrect) correct++;
      correctAnswers[question.id] = isCorrect;
    }

    const score = Math.round((correct / quiz.questions.length) * 100);
    const passed = score >= quiz.passing_score;

    return { passed, score, correct_answers: correctAnswers };
  }

  // Statistics
  async getStats() {
    const [totalCourses, totalEnrollments, certificatesIssued] =
      await Promise.all([
        this.redis.scard("courses:all"),
        this.redis.keys("enrollment:*").then((k) => k.length),
        this.redis.keys("enrollment:*").then(async (k) => {
          let count = 0;
          for (const key of k) {
            const data = await this.redis.get(key);
            if (data) {
              const e: Enrollment = JSON.parse(data);
              if (e.certificate_issued) count++;
            }
          }
          return count;
        }),
      ]);

    return {
      total_courses: totalCourses,
      total_enrollments: totalEnrollments,
      certificates_issued: certificatesIssued,
    };
  }

  // Initialize with sample courses
  async initializeSampleData() {
    const existingCourses = await this.redis.scard("courses:all");
    if (existingCourses > 0) return;

    const sampleCourses: Omit<Course, "id" | "created_at" | "updated_at">[] = [
      {
        title: "Cybersécurité Fondamentale",
        description:
          "Apprenez les bases de la cybersécurité, les menaces courantes et comment s'en protéger.",
        level: "beginner",
        duration_hours: 20,
        instructor: "Mamadou Diallo",
        tags: ["cybersecurity", "fundamentals", "beginner"],
        price: 25000,
        currency: "XOF",
        published: true,
        modules: [
          {
            id: "mod1",
            title: "Introduction à la Cybersécurité",
            description: "Comprendre les enjeux de la cybersécurité",
            order: 1,
            lessons: [
              {
                id: "l1",
                title: "Qu'est-ce que la cybersécurité?",
                type: "video",
                content: "https://academy.afri-secure.com/videos/intro",
                duration_minutes: 15,
                order: 1,
              },
              {
                id: "l2",
                title: "Histoire des cyberattaques",
                type: "text",
                content: "# Histoire...",
                duration_minutes: 10,
                order: 2,
              },
              {
                id: "l3",
                title: "Quiz: Introduction",
                type: "quiz",
                content: "quiz:l1",
                duration_minutes: 10,
                order: 3,
              },
            ],
          },
          {
            id: "mod2",
            title: "Les Menaces Informatiques",
            description: "Types de malware et vecteurs d'attaque",
            order: 2,
            lessons: [
              {
                id: "l4",
                title: "Virus et Malwares",
                type: "video",
                content: "https://academy.afri-secure.com/videos/malware",
                duration_minutes: 20,
                order: 1,
              },
              {
                id: "l5",
                title: "Phishing et Ingénierie Sociale",
                type: "video",
                content: "https://academy.afri-secure.com/videos/phishing",
                duration_minutes: 25,
                order: 2,
              },
            ],
          },
        ],
      },
      {
        title: "SOC Analyst Certification Prep",
        description:
          "Préparez-vous à la certification SOC Analyst avec des labs pratiques.",
        level: "intermediate",
        duration_hours: 40,
        instructor: "Aminata Touré",
        tags: ["soc", "certification", "siem", "intermediate"],
        price: 75000,
        currency: "XOF",
        published: true,
        modules: [
          {
            id: "mod1",
            title: "SIEM Fundamentals",
            description: "Maîtrisez les concepts des SIEM",
            order: 1,
            lessons: [
              {
                id: "l1",
                title: "Qu'est-ce qu'un SIEM?",
                type: "video",
                content: "https://academy.afri-secure.com/videos/siem-intro",
                duration_minutes: 20,
                order: 1,
              },
              {
                id: "l2",
                title: "Lab: Configuration d'Elastic SIEM",
                type: "lab",
                content: "lab:elastic",
                duration_minutes: 60,
                order: 2,
              },
            ],
          },
        ],
      },
      {
        title: "Advanced Threat Hunting",
        description:
          "Techniques avancées de détection et de chasse aux menaces.",
        level: "advanced",
        duration_hours: 60,
        instructor: "Expert International",
        tags: ["threat-hunting", "apt", "advanced"],
        price: 150000,
        currency: "XOF",
        published: true,
        modules: [],
      },
    ];

    for (const course of sampleCourses) {
      await this.createCourse(course);
    }

    log.info("Sample courses initialized");
  }
}

// Fastify API
export async function buildApp(
  academy: AcademyService,
): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  await academy.initializeSampleData();

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Courses
  app.get("/api/v1/academy/courses", async (request) => {
    const { level, tag, published } = request.query as {
      level?: string;
      tag?: string;
      published?: string;
    };

    return academy.listCourses({
      level,
      tag,
      published: published === "true",
    });
  });

  app.get<{ Params: { id: string } }>(
    "/api/v1/academy/courses/:id",
    async (request) => {
      const course = await academy.getCourse(request.params.id);
      if (!course) {
        return { error: "Course not found" };
      }
      return course;
    },
  );

  const courseSchema = z.object({
    title: z.string(),
    description: z.string(),
    level: z.enum(["beginner", "intermediate", "advanced"]),
    duration_hours: z.number(),
    modules: z.array(z.any()),
    instructor: z.string(),
    tags: z.array(z.string()),
    price: z.number(),
    currency: z.string().default("XOF"),
    published: z.boolean().default(false),
  });

  app.post<{ Body: z.infer<typeof courseSchema> }>(
    "/api/v1/academy/courses",
    { schema: { body: courseSchema } },
    async (request) => {
      return academy.createCourse(request.body);
    },
  );

  // Enrollments
  app.post<{ Body: { user_id: string; course_id: string } }>(
    "/api/v1/academy/enroll",
    async (request) => {
      const { user_id, course_id } = request.body;
      return academy.enrollUser(user_id, course_id);
    },
  );

  app.get<{ Params: { userId: string } }>(
    "/api/v1/academy/enrollments/:userId",
    async (request) => {
      return academy.getUserEnrollments(request.params.userId);
    },
  );

  // Progress
  app.post<{
    Body: { enrollment_id: string; lesson_id: string; time_spent: number };
  }>("/api/v1/academy/progress", async (request) => {
    const { enrollment_id, lesson_id, time_spent } = request.body;
    return academy.updateProgress(enrollment_id, lesson_id, time_spent);
  });

  // Quizzes
  app.get<{ Params: { lessonId: string } }>(
    "/api/v1/academy/quiz/:lessonId",
    async (request) => {
      const quiz = await academy.getQuiz(request.params.lessonId);
      if (!quiz) return { error: "Quiz not found" };

      // Don't send correct answers
      const { correct_answer, ...safeQuiz } = quiz;
      return safeQuiz;
    },
  );

  app.post<{ Params: { lessonId: string }; Body: Record<string, string> }>(
    "/api/v1/academy/quiz/:lessonId/submit",
    async (request) => {
      return academy.submitQuiz(request.params.lessonId, request.body);
    },
  );

  // Statistics
  app.get("/api/v1/academy/stats", async () => {
    return academy.getStats();
  });

  return app;
}

// Main
async function main() {
  const academy = new AcademyService();

  const app = await buildApp(academy);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`Academy API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
