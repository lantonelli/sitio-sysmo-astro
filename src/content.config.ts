import { glob } from "astro/loaders";
import { defineCollection, z } from "astro:content";

const homepageCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/homepage" }),
  schema: z.object({
    hero_slider: z.object({
      enable: z.boolean().default(true),
      slider_item: z.array(
        z.object({
          subtitle: z.string(),
          title: z.string(),
          content: z.string(),
          bg_image: z.string(),
          button: z.object({
            enable: z.boolean().default(true),
            label: z.string(),
            link: z.string(),
          }),
        }),
      ),
    }),
    banner_feature: z.object({
      enable: z.boolean().default(true),
      feature_item: z.array(
        z.object({
          name: z.string(),
          icon: z.string(),
          content: z.string(),
        }),
      ),
    }),
    funfacts: z.object({
      enable: z.boolean().default(true),
      funfacts_item: z.array(
        z.object({
          name: z.string(),
          count: z.string(),
          icon: z.string(),
        }),
      ),
    }),
    feature: z.object({
      enable: z.boolean().default(true),
      subtitle: z.string(),
      title: z.string(),
      image: z.string(),
      content: z.string(),
      feature_item: z.array(
        z.object({
          name: z.string(),
          icon: z.string(),
          content: z.string(),
        }),
      ),
    }),
    latest_news: z.object({
      enable: z.boolean().default(true),
      show_item: z.number(),
      title: z.string(),
      sub_title: z.string(),
    }),
  }),
});

// Blog collection schema
const blogCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/blog" }),
  schema: z.object({
    title: z.string(),
    meta_title: z.string().optional(),
    description: z.string().optional(),
    date: z.date().optional(),
    image: z.string().optional(),
    author: z.string().default("Admin"),
    categories: z.array(z.string()).default(["others"]),
    tags: z.array(z.string()).default(["others"]),
    draft: z.boolean().optional(),
  }),
});

// projects
const projectsCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/projects" }),
  schema: z.object({
    subtitle: z.string().optional(),
    title: z.string(),
    meta_title: z.string().optional(),
    description: z.string(),
    bg_image: z.string().optional(),
    date: z.date().optional(),
    button: z
      .object({
        enable: z.boolean(),
        label: z.string(),
        link: z.string(),
      })
      .optional(),
    image: z.string().optional(),
    client: z.string().optional(),
    category: z.string().optional(),
    status: z.string().optional(),
  }),
});

// Author collection schema
const authorsCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/authors" }),
  schema: z.object({
    title: z.string(),
    meta_title: z.string().optional(),
    email: z.string().optional(),
    image: z.string().optional(),
    description: z.string().optional(),
    designation: z.string().optional(),
    social: z
      .array(
        z
          .object({
            name: z.string().optional(),
            icon: z.string().optional(),
            link: z.string().optional(),
          })
          .optional(),
      )
      .optional(),
    draft: z.boolean().optional(),
  }),
});

// Pages collection schema
const pagesCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/pages" }),
  schema: z.object({
    title: z.string(),
    meta_title: z.string().optional(),
    description: z.string().optional(),
    image: z.string().optional(),
    draft: z.boolean().optional(),
  }),
});

const teamCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/team" }),
  schema: z.object({
    title: z.string(),
    meta_title: z.string().optional(),
    subtitle: z.string().optional(),
    description: z.string(),
    bg_image: z.string().optional(),
    draft: z.boolean().optional(),
    name: z.string().optional(),
    image: z.string().optional(),
    designation: z.string().optional(),
    social: z
      .array(
        z.object({
          name: z.string(),
          icon: z.string(),
          link: z.string(),
        }),
      )
      .optional(),
    skill_title: z.string().optional(),
    skills: z
      .array(
        z.object({
          label: z.string(),
          percentage: z.string(),
        }),
      )
      .optional(),
  }),
});

// Contact collection schema
const contactCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/contact" }),
  schema: z.object({
    title: z.string(),
    meta_title: z.string().optional(),
    description: z.string(),
    image: z.string().optional(),
    draft: z.boolean().optional(),
  }),
});

const aboutCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/about" }),
  schema: z.object({
    title: z.string(),
    meta_title: z.string(),
    description: z.string(),
    image: z.string().optional(),
    draft: z.boolean(),
    philosophy_section: z.object({
      enable: z.boolean(),
      items: z.array(
        z.object({
          title: z.string(),
          content: z.string(),
          list: z.array(z.string()),
        }),
      ),
    }),
    about_section: z.object({
      enable: z.boolean(),
      subtitle: z.string(),
      title: z.string(),
      content: z.string(),
      bg_image: z.string(),
      image: z.string(),
      button: z.object({
        enable: z.boolean(),
        label: z.string(),
        link: z.string(),
      }),
    }),
  }),
});

const serviceCollection = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/services" }),
  schema: z.object({
    title: z.string(),
    meta_title: z.string().optional(),
    subtitle: z.string().optional(),
    description: z.string(),
    bg_image: z.string().optional(),
    draft: z.boolean().optional(),
    image: z.string().optional(),
    icon: z.string().optional(),
    principal: z.boolean().optional(),
    pdf: z
      .object({
        enable: z.boolean(),
        title: z.string(),
        file: z.string(),
        size: z.string(),
      })
      .optional(),
  }),
});

// Content schema
const contentSchema = defineCollection({
  loader: glob({ pattern: "**/*.{md,mdx}", base: "src/content/contact" }),
  schema: z.object({
    banner: z
      .object({
        title: z.string(),
        content: z.string(),
        image: z.string(),
        button: z.object({
          enable: z.boolean(),
          label: z.string(),
          link: z.string(),
        }),
      })
      .optional(),
    features: z
      .array(
        z.object({
          title: z.string(),
          image: z.string(),
          content: z.string(),
          bulletpoints: z.array(z.string()),
          button: z.object({
            enable: z.boolean(),
            label: z.string().optional(),
            link: z.string().optional(),
          }),
        }),
      )
      .optional(),
  }),
});

// Testimonial schema
const testimonialCollection = defineCollection({
  loader: glob({
    pattern: "*/testimonial.{md,mdx}",
    base: "src/content/sections",
  }),
  schema: z.object({
    enable: z.boolean(),
    title: z.string(),
    subtitle: z.string().optional(),
    testimonials: z.array(
      z.object({
        name: z.string(),
        designation: z.string(),
        avatar: z.string(),
        content: z.string(),
      }),
    ),
  }),
});

// Call to Action schema
const callToActionSchema = defineCollection({
  loader: glob({
    pattern: "*/call-to-action.{md,mdx}",
    base: "src/content/sections",
  }),
  schema: z.object({
    enable: z.boolean(),
    title: z.string(),
    image: z.string().optional(),
    description: z.string().optional(),
    button: z
      .object({
        enable: z.boolean(),
        label: z.string(),
        link: z.string(),
      })
      .optional(),
  }),
});

// Export collections
export const collections = {
  homepage: homepageCollection,
  blog: blogCollection,
  projects: projectsCollection,
  authors: authorsCollection,
  pages: pagesCollection,
  team: teamCollection,
  contact: contactCollection,
  about: aboutCollection,
  services: serviceCollection,
  content: contentSchema,
  testimonials: testimonialCollection,
  callToAction: callToActionSchema,
};
