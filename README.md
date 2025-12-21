# Food Queue Reservation API

ระบบ Backend API สำหรับระบบจองคิวอาหาร พัฒนาด้วย Elysia (Bun Runtime)

## Tech Stack

- **Runtime**: Bun
- **Framework**: Elysia
- **Database**: PostgreSQL (Neon Serverless)
- **ORM**: Prisma
- **Auth**: Google OAuth 2.0 + Session-based
- **Storage**: Cloudinary
- **Documentation**: OpenAPI/Swagger

## Quick Start

### 1. ติดตั้ง Dependencies

```bash
cd backend
bun install
```

### 2. ตั้งค่า Environment Variables

```bash
cp .env.example .env
# แก้ไขค่าใน .env ตามความเหมาะสม
```

### 3. Generate Prisma Client

```bash
bun run db:generate
```

### 4. Run Migrations

```bash
bun run db:push
# หรือ
bun run db:migrate
```

### 5. Seed Database (Optional)

```bash
bun run db:seed
```

### 6. Start Development Server

```bash
bun run dev
```

Server จะรันที่ `http://localhost:3001`

## Docker

### Build และ Run

```bash
docker compose up -d
```

### ดู Logs

```bash
docker compose logs -f api
```

## API Documentation

เปิด Swagger UI ที่: `http://localhost:3001/docs`

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | สมัครสมาชิก |
| POST | `/api/auth/login` | เข้าสู่ระบบ |
| GET | `/api/auth/google` | Login ด้วย Google |
| GET | `/api/auth/me` | ดูข้อมูล user ปัจจุบัน |
| POST | `/api/auth/logout` | ออกจากระบบ |
| POST | `/api/auth/logout-all` | ออกจากทุก session |

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users/me` | ดูโปรไฟล์ตัวเอง |
| PATCH | `/api/users/me` | แก้ไขโปรไฟล์ |
| GET | `/api/users` | รายการ users ทั้งหมด (Admin) |
| PATCH | `/api/users/:id/role` | แก้ไข role (Admin) |

### Vendors

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vendors` | รายการร้านค้าทั้งหมด |
| GET | `/api/vendors/:id` | ข้อมูลร้านค้า |
| POST | `/api/vendors` | สร้างร้านค้า |
| PATCH | `/api/vendors/:id` | แก้ไขร้านค้า |
| POST | `/api/vendors/:id/toggle-status` | เปิด/ปิดร้าน |
| GET | `/api/vendors/:id/stats` | สถิติร้านค้า |

### Menu Items

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vendors/:vendorId/menu` | รายการเมนูของร้าน |
| POST | `/api/vendors/:vendorId/menu` | เพิ่มเมนู |
| PATCH | `/api/menu/:id` | แก้ไขเมนู |
| DELETE | `/api/menu/:id` | ลบเมนู |
| POST | `/api/menu/:id/toggle-availability` | เปิด/ปิดเมนู |

### Reservations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/reservations` | สร้างการจอง |
| GET | `/api/reservations/me` | การจองของฉัน |
| GET | `/api/reservations/:id` | รายละเอียดการจอง |
| PATCH | `/api/reservations/:id/status` | อัปเดตสถานะ |
| POST | `/api/reservations/:id/cancel` | ยกเลิกการจอง |
| GET | `/api/vendors/:vendorId/reservations` | การจองของร้าน |

### Time Slots

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/time-slots` | รายการ time slots |
| GET | `/api/time-slots/available` | Time slots ที่ว่าง |
| POST | `/api/time-slots` | สร้าง time slot |
| PATCH | `/api/time-slots/:id` | แก้ไข time slot |

### Uploads

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/uploads` | อัปโหลดไฟล์ |
| POST | `/api/uploads/avatar` | อัปโหลด avatar |
| POST | `/api/uploads/vendor/:id` | อัปโหลดรูปร้าน |
| POST | `/api/uploads/menu/:id` | อัปโหลดรูปเมนู |

### API Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/api-keys` | รายการ API keys |
| POST | `/api/api-keys` | สร้าง API key |
| POST | `/api/api-keys/:id/revoke` | เพิกถอน API key |
| POST | `/api/api-keys/:id/rotate` | หมุนเปลี่ยน API key |

## Request/Response Examples

### Login

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "student@school.com",
    "password": "customer123"
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "clu...",
      "email": "student@school.com",
      "name": "student",
      "role": "CUSTOMER"
    },
    "token": "abc123...",
    "expiresAt": "2024-03-20T..."
  },
  "message": "Login successful"
}
```

### Get Vendors

```bash
curl http://localhost:3001/api/vendors
```

Response:
```json
{
  "success": true,
  "data": [
    {
      "id": "clu...",
      "name": "ร้านข้าวแกง ป้าแดง",
      "description": "อาหารไทยรสชาติจัดจ้าน",
      "rating": 4.5,
      "isOpen": true,
      "categories": ["อาหารไทย", "ข้าวแกง"]
    }
  ],
  "meta": {
    "page": 1,
    "limit": 20,
    "total": 6,
    "totalPages": 1
  }
}
```

### Create Reservation

```bash
curl -X POST http://localhost:3001/api/reservations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "vendorId": "clu...",
    "timeSlotId": "clu...",
    "customerName": "ธนกร",
    "customerContact": "0800000000",
    "paymentMethod": "CASH",
    "items": [
      { "menuItemId": "clu...", "quantity": 2 }
    ]
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "clu...",
    "queueNumber": 12,
    "status": "PENDING",
    "totalAmount": 90,
    "items": [...],
    "vendor": {...},
    "timeSlot": {...}
  },
  "message": "Reservation created successfully"
}
```

## Authentication

### Bearer Token

```bash
curl -H "Authorization: Bearer <token>" http://localhost:3001/api/users/me
```

### API Key

```bash
curl -H "X-API-Key: rk_abc123..." http://localhost:3001/api/vendors
```

## Demo Accounts

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@school.com | admin123 |
| Vendor | vendor1@shop.com | vendor123 |
| Customer | student@school.com | customer123 |

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| DATABASE_URL | PostgreSQL connection string | Yes |
| JWT_SECRET | Secret key for JWT | Yes |
| GOOGLE_CLIENT_ID | Google OAuth client ID | Yes |
| GOOGLE_CLIENT_SECRET | Google OAuth client secret | Yes |
| GOOGLE_CALLBACK_URL | OAuth callback URL | Yes |
| CLOUDINARY_CLOUD_NAME | Cloudinary cloud name | Yes |
| CLOUDINARY_API_KEY | Cloudinary API key | Yes |
| CLOUDINARY_API_SECRET | Cloudinary API secret | Yes |
| FRONTEND_URL | Frontend URL for CORS | No |
| PORT | Server port (default: 3001) | No |

## Project Structure

```
backend/
├── src/
│   ├── config/           # Configuration files
│   │   ├── env.ts        # Environment variables
│   │   ├── database.ts   # Prisma client
│   │   └── cloudinary.ts # Cloudinary config
│   ├── controllers/      # Route handlers
│   ├── services/         # Business logic
│   ├── middlewares/      # Custom middlewares
│   ├── utils/            # Utility functions
│   ├── prisma/           # Prisma seed
│   ├── app.ts            # Elysia app setup
│   └── index.ts          # Entry point
├── prisma/
│   └── schema.prisma     # Database schema
├── Dockerfile
├── docker-compose.yml
└── package.json
```

## เชื่อมต่อกับ Frontend

### 1. ตั้งค่า API Base URL

```typescript
// frontend/lib/api.ts
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api';
```

### 2. สร้าง API Client

```typescript
// frontend/lib/api-client.ts
export const apiClient = {
  async request(endpoint: string, options?: RequestInit) {
    const token = localStorage.getItem('token');

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options?.headers,
      },
    });

    return response.json();
  },

  get: (endpoint: string) => apiClient.request(endpoint),
  post: (endpoint: string, data: any) =>
    apiClient.request(endpoint, { method: 'POST', body: JSON.stringify(data) }),
  patch: (endpoint: string, data: any) =>
    apiClient.request(endpoint, { method: 'PATCH', body: JSON.stringify(data) }),
  delete: (endpoint: string) =>
    apiClient.request(endpoint, { method: 'DELETE' }),
};
```

### 3. อัปเดต Auth Context

```typescript
// frontend/lib/auth-context.tsx
import { apiClient } from './api-client';

export const AuthProvider = ({ children }) => {
  const login = async (email: string, password: string) => {
    const response = await apiClient.post('/auth/login', { email, password });
    if (response.success) {
      localStorage.setItem('token', response.data.token);
      setUser(response.data.user);
    }
    return response;
  };

  // ... อื่นๆ
};
```

### 4. อัปเดต Vendor Context

```typescript
// frontend/lib/vendor-context.tsx
import { apiClient } from './api-client';

export const VendorProvider = ({ children }) => {
  const fetchVendors = async () => {
    const response = await apiClient.get('/vendors?isOpen=true');
    if (response.success) {
      setVendors(response.data);
    }
  };

  const createReservation = async (data: CreateReservationInput) => {
    const response = await apiClient.post('/reservations', data);
    return response;
  };

  // ... อื่นๆ
};
```

## License

MIT
# Reservation-BE
