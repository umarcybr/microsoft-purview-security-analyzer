# How to Upload Microsoft Purview Security Analyzer to GitHub

This guide will walk you through uploading your security analyzer project to GitHub step by step.

## Prerequisites

Before starting, make sure you have:
- A GitHub account (create one at https://github.com if you don't have one)
- Git installed on your computer
- Your project files ready

## Step 1: Prepare Your Project Files

First, make sure all your project files are organized correctly. Your project should have this structure:

```
microsoft-purview-security-analyzer/
├── app_new.py                 # Main application
├── security_analyzer.py      # Core analysis functions
├── attached_assets/
│   └── GeoLite2-City.mmdb   # GeoIP database
├── .streamlit/
│   └── config.toml           # App configuration
├── .gitignore                # Git ignore file
├── README.md                 # Project documentation
├── LICENSE                   # MIT license
├── pyproject.toml           # Python dependencies
├── setup.py                 # Installation script
├── INSTALLATION.md          # Installation guide
├── CONTRIBUTING.md          # Contribution guidelines
├── DEPLOYMENT.md            # Deployment instructions
└── DEVELOPMENT.md           # Development guide
```

## Step 2: Create a New Repository on GitHub

1. **Go to GitHub**: Open https://github.com in your web browser
2. **Sign in**: Log in to your GitHub account
3. **Create Repository**: Click the green "New" button or the "+" icon in the top right corner
4. **Repository Details**:
   - **Repository name**: `microsoft-purview-security-analyzer`
   - **Description**: `A web-based security analysis tool for Microsoft Purview audit logs`
   - **Visibility**: Choose "Public" (recommended for open source) or "Private"
   - **Initialize**: 
     - ✅ Do NOT check "Add a README file" (we already have one)
     - ✅ Do NOT add .gitignore (we already have one)
     - ✅ Choose "MIT License" if you want to add a license
5. **Create**: Click "Create repository"

## Step 3: Download Your Project Files

If you're working on Replit, you need to download your project files first:

### Option A: Download as ZIP (Easiest)
1. In your Replit project, click on the three dots menu
2. Select "Download as ZIP"
3. Extract the ZIP file to a folder on your computer
4. Navigate to that folder in your terminal/command prompt

### Option B: Clone from Replit (if available)
```bash
# If Replit provides a git URL, you can clone it
git clone YOUR_REPLIT_GIT_URL
cd microsoft-purview-security-analyzer
```

## Step 4: Initialize Git and Upload to GitHub

Open your terminal/command prompt and navigate to your project folder, then run these commands:

### Initialize Git Repository
```bash
# Navigate to your project folder
cd path/to/your/microsoft-purview-security-analyzer

# Initialize git repository
git init

# Add all files to git
git add .

# Make your first commit
git commit -m "Initial commit: Microsoft Purview Security Analyzer with custom filtering"
```

### Connect to GitHub and Push
```bash
# Add GitHub repository as remote origin
# Replace YOUR_USERNAME with your actual GitHub username
git remote add origin https://github.com/YOUR_USERNAME/microsoft-purview-security-analyzer.git

# Rename main branch (if needed)
git branch -M main

# Push to GitHub
git push -u origin main
```

## Step 5: Verify Upload

1. **Go to your repository**: Visit `https://github.com/YOUR_USERNAME/microsoft-purview-security-analyzer`
2. **Check files**: Verify all your files are uploaded correctly
3. **View README**: GitHub should display your README.md file automatically

## Step 6: Configure Repository Settings

### Add Topics (Tags)
1. Go to your repository page
2. Click the gear icon next to "About"
3. Add topics: `security`, `audit-logs`, `streamlit`, `microsoft-purview`, `python`, `cybersecurity`

### Enable GitHub Pages (Optional)
If you want to showcase your project documentation:
1. Go to Settings → Pages
2. Select "Deploy from a branch"
3. Choose "main" branch and "/ (root)" folder
4. Your documentation will be available at `https://YOUR_USERNAME.github.io/microsoft-purview-security-analyzer`

## Step 7: Create Releases

To create proper releases of your software:

1. **Go to Releases**: Click "Releases" on your repository page
2. **Create Release**: Click "Create a new release"
3. **Tag Version**: Enter `v1.0.0` (or appropriate version)
4. **Release Title**: "Microsoft Purview Security Analyzer v1.0.0"
5. **Description**: Describe the features and capabilities
6. **Publish**: Click "Publish release"

## Common Issues and Solutions

### Issue: Authentication Error
**Solution**: Use a Personal Access Token instead of password
1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate a new token with "repo" permissions
3. Use your username and token as password when prompted

### Issue: Large File Error
**Solution**: The GeoLite2 database might be too large
```bash
# Check file sizes
ls -lh attached_assets/

# If GeoLite2-City.mmdb is over 100MB, use Git LFS
git lfs track "*.mmdb"
git add .gitattributes
git commit -m "Add Git LFS tracking for database files"
```

### Issue: Files Not Showing
**Solution**: Check your .gitignore file
```bash
# View what files are being ignored
cat .gitignore

# Check git status
git status
```

## Alternative: Using GitHub Desktop

If you prefer a graphical interface:

1. **Download GitHub Desktop**: Get it from https://desktop.github.com
2. **Sign in**: Log in with your GitHub account
3. **Clone or Add**: 
   - If starting fresh: "Clone a repository from the Internet" → "Create new repository"
   - If you have files: "Add an existing repository from your hard drive"
4. **Publish**: Click "Publish repository" to upload to GitHub

## Next Steps

After uploading to GitHub:

1. **Star your repository**: Click the star button to bookmark it
2. **Share**: Share the repository URL with others
3. **Collaborate**: Others can now fork, clone, and contribute to your project
4. **Issues**: Use GitHub Issues to track bugs and feature requests
5. **Wiki**: Create documentation in the repository wiki

## Repository URL Structure

Your repository will be available at:
- **Main page**: `https://github.com/YOUR_USERNAME/microsoft-purview-security-analyzer`
- **Raw files**: `https://raw.githubusercontent.com/YOUR_USERNAME/microsoft-purview-security-analyzer/main/README.md`
- **Clone URL**: `https://github.com/YOUR_USERNAME/microsoft-purview-security-analyzer.git`

## Security Considerations

Since this is a security tool:
- Consider making the repository public to benefit the security community
- Include clear documentation about responsible use
- Add security contact information
- Consider adding a security policy file (SECURITY.md)

Remember to replace `YOUR_USERNAME` with your actual GitHub username throughout these commands!