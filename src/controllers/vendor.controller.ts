// Vendor Controller
import { Elysia, t } from "elysia";
import * as vendorService from "../services/vendor.service";
import { validateSession, type AuthUser } from "../services/auth.service";
import {
  authPlugin,
  requireAuth,
  requireVendorOrAdmin,
  requireAdmin,
} from "../middlewares/auth.middleware";
import { success, paginated } from "../utils/response";
import {
  createVendorSchema,
  updateVendorSchema,
  paginationSchema,
} from "../utils/validation";
import { BadRequestError, UnauthorizedError } from "../utils/errors";

// Helper function to extract and validate auth
async function getAuthUser(request: Request): Promise<AuthUser> {
  const authHeader = request.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    throw new UnauthorizedError("Authentication required");
  }

  const token = authHeader.slice(7);
  const user = await validateSession(token);

  if (!user) {
    throw new UnauthorizedError("Invalid or expired session");
  }

  return user;
}

export const vendorController = new Elysia({ prefix: "/vendors" })
  // Public routes
  .use(authPlugin)

  // Get all vendors (public)
  .get(
    "/",
    async ({ query }) => {
      const paginationResult = paginationSchema.safeParse(query);

      const pagination = paginationResult.success
        ? paginationResult.data
        : { page: 1, limit: 10 };

      const result = await vendorService.getAllVendors(pagination, {
        isOpen:
          query.isOpen === "true"
            ? true
            : query.isOpen === "false"
              ? false
              : undefined,
        category: query.category,
        search: query.search,
      });

      return paginated(result);
    },
    {
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
        isOpen: t.Optional(t.String()),
        category: t.Optional(t.String()),
        search: t.Optional(t.String()),
      }),
      detail: {
        tags: ["Vendors"],
        summary: "List all vendors",
        description: "Get all vendors with optional filters",
      },
    },
  )

  // Get all categories
  .get(
    "/categories",
    async () => {
      const categories = await vendorService.getAllCategories();
      return success(categories);
    },
    {
      detail: {
        tags: ["Vendors"],
        summary: "Get all categories",
        description: "Get list of all vendor categories",
      },
    },
  )

  // Get vendor by ID (public)
  .get(
    "/:vendorId",
    async ({ params }) => {
      const vendor = await vendorService.getVendorById(params.vendorId);
      return success(vendor);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      detail: {
        tags: ["Vendors"],
        summary: "Get vendor by ID",
        description: "Get vendor details",
      },
    },
  )

  // Protected routes
  .use(requireAuth)

  // Get my vendor profile
  .get(
    "/me/profile",
    async ({ request }) => {
      const user = await getAuthUser(request);
      const vendor = await vendorService.getVendorByUserId(user.id);
      return success(vendor);
    },
    {
      detail: {
        tags: ["Vendors"],
        summary: "Get my vendor profile",
        description: "Get current user vendor profile",
      },
    },
  )

  // Create vendor (become a vendor)
  .post(
    "/",
    async ({ request, body }) => {
      const user = await getAuthUser(request);
      const validated = createVendorSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const vendor = await vendorService.createVendor(user.id, validated.data);
      return success(vendor, "Vendor profile created");
    },
    {
      body: t.Object({
        name: t.String(),
        description: t.Optional(t.String()),
        image: t.Optional(t.String()),
        categories: t.Optional(t.Array(t.String())),
      }),
      detail: {
        tags: ["Vendors"],
        summary: "Create vendor",
        description: "Create a vendor profile (become a vendor)",
      },
    },
  )

  // Vendor/Admin routes
  .use(requireVendorOrAdmin)

  // Update vendor
  .patch(
    "/:vendorId",
    async ({ request, params, body }) => {
      const user = await getAuthUser(request);
      const validated = updateVendorSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const vendor = await vendorService.updateVendor(
        params.vendorId,
        user.id,
        user.role,
        validated.data,
      );
      return success(vendor, "Vendor updated");
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      body: t.Object({
        name: t.Optional(t.String()),
        description: t.Optional(t.String()),
        image: t.Optional(t.String()),
        isOpen: t.Optional(t.Boolean()),
        categories: t.Optional(t.Array(t.String())),
      }),
      detail: {
        tags: ["Vendors"],
        summary: "Update vendor",
        description: "Update vendor details",
      },
    },
  )

  // Toggle vendor status
  .post(
    "/:vendorId/toggle-status",
    async ({ request, params }) => {
      const user = await getAuthUser(request);
      const vendor = await vendorService.toggleVendorStatus(
        params.vendorId,
        user.id,
        user.role,
      );
      return success(
        vendor,
        `Shop is now ${vendor.isOpen ? "open" : "closed"}`,
      );
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      detail: {
        tags: ["Vendors"],
        summary: "Toggle vendor status",
        description: "Open/close vendor shop",
      },
    },
  )

  // Get vendor statistics
  .get(
    "/:vendorId/stats",
    async ({ params }) => {
      const stats = await vendorService.getVendorStats(params.vendorId);
      return success(stats);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      detail: {
        tags: ["Vendors"],
        summary: "Get vendor stats",
        description: "Get vendor statistics",
      },
    },
  )

  // Admin routes
  .use(requireAdmin)

  // Delete vendor (admin)
  .delete(
    "/:vendorId",
    async ({ params }) => {
      await vendorService.deleteVendor(params.vendorId);
      return success(null, "Vendor deleted");
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      detail: {
        tags: ["Vendors"],
        summary: "Delete vendor",
        description: "Delete vendor (admin only)",
      },
    },
  );
