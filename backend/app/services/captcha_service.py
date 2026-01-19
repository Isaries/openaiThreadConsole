import random

class CaptchaService:
    @staticmethod
    def generate(mode='normal'):
        """
        Generates a CAPTCHA based on the specified mode.
        Returns:
            dict: {
                'image': bytes (SVG XML),
                'answer': str (The expected answer),
                'content_type': 'image/svg+xml'
            }
        """
        if mode == 'math':
            return CaptchaService._generate_math_problem()
        else:
            return CaptchaService._generate_text_code()

    @staticmethod
    def _generate_text_code():
        # 1. Generate Random String (4 chars, no confusing chars)
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        code = ''.join(random.choices(chars, k=4))
        
        # 2. Create SVG
        svg_content = CaptchaService._create_svg_xml(code, is_math=False)
        
        return {
            'image': svg_content.encode('utf-8'),
            'answer': code,  # Case-insensitive check needed later
            'content_type': 'image/svg+xml'
        }

    @staticmethod
    def _generate_math_problem():
        # Generate: d/dx (ax^n + bx) | x=c
        # To keep it simple but look "hard":
        # a, b in [2..5]
        # n in [2, 3]
        # c in [1, 2, 3]
        
        a = random.randint(2, 5)
        b = random.randint(2, 9)
        n = random.randint(2, 3)
        c = random.randint(1, 3)
        
        # Question String for SVG: "d/dx ( {a}x^{n} + {b}x ) | x={c}"
        if n == 2:
            term1 = f"{a}x²"
        elif n == 3:
            term1 = f"{a}x³"
        else:
            term1 = f"{a}x^{n}"
            
        question_text = f"d/dx ({term1} + {b}x) ,x={c}"
        
        # Calculate Answer
        # f(x) = ax^n + bx
        # f'(x) = n*a*x^(n-1) + b
        # f'(c) = n*a*(c**(n-1)) + b
        
        ans_val = (n * a * (c ** (n - 1))) + b
        
        svg_content = CaptchaService._create_svg_xml(question_text, is_math=True)
        
        return {
            'image': svg_content.encode('utf-8'),
            'answer': str(ans_val),
            'content_type': 'image/svg+xml'
        }

    @staticmethod
    def _create_svg_xml(text, is_math=False):
        """
        Creates a raw SVG string with noise and the given text.
        """
        width = 200 if is_math else 120
        height = 50
        
        # Background color
        bg_color = "#f4f4f4"
        
        # Random Noise Lines
        noise_lines = ""
        for _ in range(5):
            x1 = random.randint(0, width)
            y1 = random.randint(0, height)
            x2 = random.randint(0, width)
            y2 = random.randint(0, height)
            stroke = random.choice(["#ccc", "#ddd", "#bbb"])
            noise_lines += f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="1" />'

        # Text Positioning
        # Math needs to be smaller/longer
        font_size = "20" if is_math else "28"
        font_family = "serif" if is_math else "sans-serif"
        text_x = "50%"
        text_y = "60%"
        
        # Random slight rotation for Text (only for normal)
        transform = ""
        if not is_math:
            angle = random.randint(-5, 5)
            transform = f'transform="rotate({angle}, {width/2}, {height/2})"'
            
        text_element = f'''
        <text x="{text_x}" y="{text_y}" 
              font-family="{font_family}" font-size="{font_size}" font-weight="bold" fill="#333"
              text-anchor="middle" dominant-baseline="middle" 
              {transform}>
            {text}
        </text>
        '''

        svg = f'''
<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
    <rect width="100%" height="100%" fill="{bg_color}"/>
    {noise_lines}
    {text_element}
</svg>
        '''
        return svg.strip()
