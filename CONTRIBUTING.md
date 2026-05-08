# Contributing to security-analytics

As an open-source project, the `artisanpack-ui/security-analytics` package is open to contributions from everyone. You don't need to be a developer to contribute. Whether it's writing code, improving documentation, exercising the package against your own Laravel app and reporting bugs, or helping triage issues, there's a place for you here.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Issue Templates](#issue-templates)
- [Branching Strategy](#branching-strategy)
- [Pull Request Process](#pull-request-process)
- [Label System](#label-system)
- [Milestone Strategy](#milestone-strategy)
- [Forking and Contributing](#forking-and-contributing)
- [Naming Conventions](#naming-conventions)

## Code of Conduct

In order to make this a best place for everyone to contribute, there are some hard and fast rules that everyone needs to abide by.

* This package is open to everyone no matter your race, ethnicity, gender, who you love, etc. To keep it that way, there's zero tolerance for any racist, misogynistic, xenophobic, bigoted, Zionist, antisemitic (yes, there is a difference), Islamophobic, etc. messages. This includes messages sent to a fellow contributor outside this repository. In short, don't be a jerk. Failure to comply will result in a ban from the project.
* Be respectful when communicating with fellow contributors.
* Respect the decisions made about what belongs in the package.
* Work together to make `security-analytics` the best file-upload-security toolkit it can be.

## Ways to Contribute

There are a lot of ways to contribute to `security-analytics` even if you're not a developer. Here are some (but not all) of them:

* Write code for the package — validators, scanners, middleware, rules
* Add or improve tests, including malware-scanner test fixtures
* Test the package against your own Laravel app and report bugs
* Write documentation, examples, and recipes
* Talk about `security-analytics` on your blog or social media
* Review pull requests
* Help answer questions in issues

## Getting Started

### Prerequisites

Before contributing, make sure you have:
- Git installed on your machine
- PHP 8.1 or higher
- Composer
- A GitHub account

### Setting Up Your Development Environment

1. Fork the repository (see [Forking and Contributing](#forking-and-contributing))
2. Clone your fork locally
3. Install dependencies: `composer install`
4. Create a feature branch: `git checkout -b feature/your-feature-name`
5. Make your changes
6. Test your changes
7. Push to your fork
8. Create a merge/pull request

## Issue Templates

When creating an issue, you'll be prompted to choose a template. We have several templates to help you provide the right information:

### Bug Report Template

Use this template when you've found a bug. It will ask for:
- **Expected behavior** - What should happen
- **Current behavior** - What actually happens
- **Steps to reproduce** - How to recreate the bug
- **Environment** - Your OS, browser, PHP version, project version
- **Screenshots** - If applicable

The template automatically applies these labels:
- `Type::Bug`
- `Status::Backlog`

**You should also add:**
- `Priority::*` (Critical, High, Medium, or Low) if urgent
- `Area::*` (Frontend, Backend, etc.) for the affected area

### Feature Request Template

Use this when suggesting new functionality. It will ask for:
- **Problem statement** - What problem does this solve?
- **Proposed solution** - What would you like to happen?
- **Alternatives considered** - Other solutions you've thought about
- **Use cases** - How would this be used?

The template automatically applies:
- `Type::Feature`
- `Status::Backlog`

### Enhancement Template

Use this for improvements to existing features. It will ask for:
- **Current behavior** - How it works now
- **Proposed improvement** - How to make it better
- **Benefits** - Why this improvement is valuable
- **Backwards compatibility** - Will this break anything?

The template automatically applies:
- `Type::Enhancement`
- `Status::Backlog`

### Task Template

Use this for general tasks that don't fit other categories. It will ask for:
- **Task description** - What needs to be done
- **Acceptance criteria** - How we know it's complete
- **Context** - Why this is needed

The template automatically applies:
- `Status::Backlog`

### Submitting Your Issue

After filling out the template:
1. Review your issue for completeness
2. The labels will be applied automatically
3. Add any additional labels if needed (Priority, Area)
4. Submit the issue
5. A maintainer will review and triage it

**Note:** New issues are initially unassigned to a milestone. A maintainer assigns one during triage — `Future Release` for ideas under consideration without a timeline, or a specific version (e.g. `v1.0`, `v1.1`) once scheduled.

## Branching Strategy

We use GitLab Flow with release branches. Here's how it works:

### Main Branches

- **`main`** - Latest stable release
  - All releases are tagged from main
  - Protected: No direct pushes allowed
  
- **`release/X.Y.x`** - Long-term support branches for patch releases
  - Example: `release/1.0.x` for v1.0.1, v1.0.2, etc.
  - Created when needed for patches

### Feature Branches

When contributing, create a feature branch:

**Format:** `feature/short-description` or `fix/short-description`

**Examples:**
- `feature/add-dark-mode`
- `fix/navigation-bug`
- `feature/issue-123-user-profiles`

### Creating Your Branch

```bash
# For new features
git checkout main
git pull origin main
git checkout -b feature/your-feature

# For bug fixes
git checkout main
git pull origin main
git checkout -b fix/your-bugfix
```

### Workflow

1. **Create branch** from `main`
2. **Make changes** and commit
3. **Push** to your fork
4. **Create PR** to `main` branch
5. **Wait for review** from maintainer
6. **Address feedback** if needed
7. **Maintainer merges** when approved

**Important:** Always create your branch from `main` and target `main` in your pull request.

## Pull Request Process

### Before Creating a Pull Request

1. **Ensure there isn't an existing PR** for the same change
2. **Create or link to an issue** - All PRs should reference an issue
3. **Test your changes** locally
4. **Run code linting** - Follow the naming conventions
5. **Update documentation** if needed

### Creating Your Pull Request

We have templates for different types of pull requests:

#### Default Template (Bug Fixes, Features, Enhancements, Tasks)

Use this for most PRs. It includes:
- Description of changes
- Type of change (Bug fix, Feature, Enhancement, etc.)
- Testing performed
- **Accessibility tests** (required for all UI changes)
- Tests added
- Documentation updates
- Pre-submission checklist

The template automatically applies:
- `Status::In Review`

**You should also add:**
- `Type::*` (Bug, Feature, Enhancement, etc.)
- `Area::*` (Frontend, Backend, etc.)

#### Release Template (Maintainers Only)

This template is for release pull requests and should only be used by maintainers.

### Pull Request Guidelines

**For External Contributors:**
1. Create your PR using the Default template
2. Fill out all sections completely
3. Link to the related issue: `Closes #123`
4. Wait for maintainer review
5. Address any feedback promptly
6. A maintainer will approve and merge your PR

**Note:** All PRs require maintainer approval. External contributors cannot merge their own PRs.

### Code Review Process

When you submit an PR:
1. A maintainer will review within 1-3 days
2. They may request changes or ask questions
3. Address feedback by pushing new commits
4. Once approved, the maintainer will merge
5. Your branch will be automatically deleted

### After Your PR is Merged

- Your changes will be included in the next release
- The related issue will automatically close
- You'll be credited in the release notes
- Thank you for contributing! 🎉

## Label System

We use a comprehensive label system to organize issues and pull requests:

### Status Labels (Workflow)

Labels that track where an issue/PR is in the workflow:
- `Status::Backlog` - Not yet prioritized
- `Status::To Do` - Ready to work on
- `Status::In Progress` - Currently being worked on
- `Status::In Review` - Under code review
- `Status::Approved` - Approved and ready to merge
- `Status::Blocked` - Cannot proceed (explain in comments)
- `Status::On Hold` - Paused temporarily

### Type Labels (What It Is)

Labels that categorize the work:
- `Type::Bug` - Something isn't working
- `Type::Feature` - New functionality
- `Type::Enhancement` - Improvement to existing feature
- `Type::Documentation` - Documentation updates
- `Type::Refactor` - Code improvement without behavior change
- `Type::Security` - Security-related changes
- `Type::Performance` - Performance improvements
- `Type::Experimental` - Experimental features

### Priority Labels (Urgency)

Labels that indicate importance:
- `Priority::Critical` - Broken functionality, needs immediate fix
- `Priority::High` - Important, should be addressed soon
- `Priority::Medium` - Normal priority
- `Priority::Low` - Nice to have, low urgency

### Area Labels (Where)

Labels that indicate affected code area:
- `Area::Frontend` - UI/client-side code
- `Area::Backend` - Server/API code
- `Area::Design` - Visual design work
- `Area::Infrastructure` - DevOps/deployment
- `Area::Testing` - Test-related work

### Special Labels

- `good first issue` - Good for new contributors
- `help wanted` - Community assistance requested
- `breaking change` - Breaks backward compatibility
- `accessibility` - Accessibility improvements

**Templates apply some labels automatically, but you may need to add others manually.**

## Milestone Strategy

We use milestones to organize and schedule work:

### How Milestones Work

- **Current Version** (e.g., `v1.0`) - Actively being developed
- **Version Planning** (e.g., `v1.x`) - Planned for future v1 releases
- **Future Release** - Nice-to-have features, no timeline yet

### For Contributors

When you create an issue:
- It's initially unassigned to a milestone
- A maintainer will assign it to a milestone during triage
- `Future Release` = under consideration but not scheduled
- `v1.x` or `v2.x` = planned for that major version
- `v1.0`, `v1.1`, etc. = scheduled for that specific release

**You don't need to assign milestones** - maintainers will handle this.

### For Maintainers

- Assign issues to specific versions when scheduled
- Use `vX.x` for planned but not yet scheduled features
- Use `Future Release` for community requests
- Create patch milestones (v1.0.1) only when needed

## Forking and Contributing

`security-analytics` is hosted on GitHub at [ArtisanPack-UI/security-analytics](https://github.com/ArtisanPack-UI/security-analytics). The fork-and-PR flow is the canonical contribution path; the Bitbucket and patch-file flows below exist for contributors who can't or don't want to use GitHub directly.

### From GitHub (Primary)

1. **Fork the repository**
   - Visit [ArtisanPack-UI/security-analytics](https://github.com/ArtisanPack-UI/security-analytics)
   - Click "Fork" — the fork will land in your account

2. **Clone your fork**
   ```bash
   git clone git@github.com:your-username/security-analytics.git
   cd security-analytics
   ```

3. **Add upstream remote**
   ```bash
   git remote add upstream git@github.com:ArtisanPack-UI/security-analytics.git
   ```

4. **Create a feature branch from `main`**
   ```bash
   git checkout -b feature/your-feature
   ```

5. **Make changes, commit, and push**
   ```bash
   git add .
   git commit -m "feat: short description"
   git push origin feature/your-feature
   ```

6. **Open a Pull Request**
   - On your fork, click "Compare & pull request"
   - Target `ArtisanPack-UI/security-analytics:main`
   - Fill out the PR template (CodeRabbit will auto-review)
   - Submit

### From Bitbucket

Bitbucket users can mirror their work to a GitHub fork before opening a PR:

1. **Clone from GitHub**
   ```bash
   git clone https://github.com/ArtisanPack-UI/security-analytics.git
   cd security-analytics
   ```

2. **Create a Bitbucket repository for your working copy**

3. **Add Bitbucket as a remote**
   ```bash
   git remote add bitbucket git@bitbucket.org:your-username/security-analytics.git
   ```

4. **Develop on a feature branch and push to Bitbucket**
   ```bash
   git checkout -b feature/your-feature
   # ... make changes ...
   git push bitbucket feature/your-feature
   ```

5. **Mirror to GitHub and open a PR**
   - Create a GitHub fork (see Primary flow above)
   - Add it as a remote and push your branch there
   - Open a PR against `ArtisanPack-UI/security-analytics:main`

### From Local Git (No Account)

If you can't use GitHub at all, submit a patch:

1. **Clone the project**
   ```bash
   git clone https://github.com/ArtisanPack-UI/security-analytics.git
   cd security-analytics
   ```

2. **Create a feature branch and make your changes**
   ```bash
   git checkout -b feature/your-feature
   git add .
   git commit -m "feat: short description"
   ```

3. **Create a patch file**
   ```bash
   git format-patch main --stdout > my-contribution.patch
   ```

4. **Submit the patch**
   - Open an issue on the GitHub tracker and attach the `.patch` file
   - Describe the change in the issue body
   - A maintainer will pick it up during triage

5. **Maintainer applies the patch**
   ```bash
   git apply my-contribution.patch
   ```

### Keeping Your Fork Updated

```bash
# Fetch upstream changes from ArtisanPack-UI/security-analytics
git fetch upstream

# Merge into your main
git checkout main
git merge upstream/main

# Push to your fork
git push origin main
```

### Contribution Workflow Summary

| Path | Difficulty | Preferred? | Notes |
|------|------------|------------|-------|
| GitHub fork + PR | ⭐ Easy | ✅ Yes | Canonical flow; CI + CodeRabbit run automatically |
| Bitbucket mirror → GitHub PR | ⭐⭐ Medium | ⚠️ Okay | Develop on Bitbucket, mirror to a GitHub fork to open the PR |
| Local patch file | ⭐⭐⭐ Advanced | ⚠️ Last resort | For contributors who can't use GitHub |

**Recommendation:** Use the GitHub fork + PR flow whenever possible — it's the smoothest path and the only one that gets automated CI + CodeRabbit feedback before maintainer review.

## Naming Conventions

To keep things consistent across the code base, it's important to follow these naming conventions:

### PHP Code

- **Class names**: Pascal Case - `ClassName`
- **Function names**: Camel Case - `functionName`
- **Variables**: Camel Case - `variableName`
- **Array keys**: Camel Case - `$array['arrayKey']`
- **Database columns**: Snake case - `table_column`
- **Constants**: Upper snake case - `CONSTANT_NAME`

### Files and Directories

- **PHP class files**: Match class name - `ClassName.php`
- **Config files**: Kebab case - `config-name.php`
- **View files**: Kebab case - `view-name.blade.php`

### Git Branches

- **Feature branches**: `feature/short-description`
- **Bug fix branches**: `fix/short-description`
- **Use hyphens** not underscores
- **Keep it short** but descriptive
- **Examples**: `feature/dark-mode`, `fix/navbar-responsive`

### Commit Messages

Follow conventional commit format:

```text
type: Short description

Longer description if needed.

Closes #123
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting)
- `refactor:` - Code refactoring
- `test:` - Test updates
- `chore:` - Maintenance tasks

**Examples:**

```text
feat: Add dark mode support

Implements dark mode theme with toggle in settings.
Includes proper color contrast for accessibility.

Closes #456
```

```text
fix: Resolve navigation menu overlap on mobile

Menu was overlapping content on screens < 768px.
Updated CSS media queries and z-index values.

Closes #789
```

## Questions?

If you have questions about contributing:

1. **Check existing documentation** - Wiki, README, this guide
2. **Search existing issues** - Your question might be answered
3. **Ask in an issue** - Create a question issue
4. **Join discussions** - Comment on relevant issues

## Thank You!

Thank you for contributing to ArtisanPack UI! Your contributions help make this project better for everyone.

Every contribution matters, whether it's:
- 🐛 Fixing a typo in documentation
- ✨ Adding a major feature
- 🧪 Writing tests
- 📝 Improving documentation
- 💡 Suggesting ideas

We appreciate your time and effort! 🎉

---

**Project Maintainer:** Jacob Martella ([@ViewFromTheBox](https://github.com/ViewFromTheBox))  
**License:** [MIT](LICENSE)
**Website:** [https://jacobmartella.me](https://jacobmartella.me)
