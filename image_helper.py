import os, sys, json
from PIL import Image
import numpy as np

def process_image(filepath, thumb_path):
    try:
        with Image.open(filepath) as img:
            img = img.convert('RGB')
            w, h = img.size
            thumb = img.copy()
            thumb.thumbnail((120, 120))
            os.makedirs(os.path.dirname(thumb_path), exist_ok=True)
            thumb.save(thumb_path, format='JPEG', quality=85)
            small = img.resize((32, 32))
            arr = np.array(small, dtype=np.float32) / 255.0
            linear = np.where(arr > 0.04045, np.power((arr + 0.055) / 1.055, 2.4), arr / 12.92)
            x = linear[:, :, 0] * 0.4124564 + linear[:, :, 1] * 0.3575761 + linear[:, :, 2] * 0.1804375
            y = linear[:, :, 0] * 0.2126729 + linear[:, :, 1] * 0.7151522 + linear[:, :, 2] * 0.0721750
            z = linear[:, :, 0] * 0.0193339 + linear[:, :, 1] * 0.1191920 + linear[:, :, 2] * 0.9503041
            xr, yr, zr = x / 0.95047, y, z / 1.08883
            delta = 6.0 / 29.0
            delta3 = delta ** 3
            fx = np.where(xr > delta3, np.cbrt(xr), xr / (3.0 * delta * delta) + 4.0 / 29.0)
            fy = np.where(yr > delta3, np.cbrt(yr), yr / (3.0 * delta * delta) + 4.0 / 29.0)
            fz = np.where(zr > delta3, np.cbrt(zr), zr / (3.0 * delta * delta) + 4.0 / 29.0)
            lab = [float(np.mean(116 * fy - 16)), float(np.mean(500 * (fx - fy))), float(np.mean(200 * (fy - fz)))]
            return {'success': True, 'width': w, 'height': h, 'avg_lab': [round(v, 2) for v in lab]}
    except Exception as e:
        return {'success': False, 'error': str(e)}

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(json.dumps({'success': False, 'error': 'Missing arguments'}))
        sys.exit(1)
    print(json.dumps(process_image(sys.argv[1], sys.argv[2])))
